// Client core for the counted hash chain. Runs unchanged in browsers and Node.
//
// store:     { load(): state|undefined, save(state) }   durable, atomic per save
// lock:      (fn) => runs fn exclusively across every context sharing the store
// transport: (params) => { status, body }  or throws on network failure
//
// Grant state: { refresh_token, n, v, next }
//   n     the step number of the challenge the AS currently holds
//   v     the verifier for that challenge: challenge_n = SHA256(v)
//   next  the verifier this client has committed to (or is about to), saved before sending

const enc = (s) => new TextEncoder().encode(s);
export const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)))
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const random = () => b64u(crypto.getRandomValues(new Uint8Array(32)));
export const H = async (s) => b64u(await crypto.subtle.digest('SHA-256', enc(s)));

export class TerminalError extends Error {}   // grant is gone: restart authorization
export class TransientError extends Error {}  // gave up for now: state intact, call again later
export class RequestError extends Error {}    // the AS rejected this request with a definitive error: state intact, do not resend

const TERMINAL = new Set(['invalid_grant', 'invalid_client']);

export async function pkcePair() {
  const verifier = random();
  return { verifier, challenge: await H(verifier) };
}

export function createClient({
  store, lock, transport, clientId,
  maxAttempts = 8,
  sleep = (ms) => new Promise((r) => setTimeout(r, ms)),
  hook = () => {},              // test-only crash points
}) {
  async function attempt(params, isComplete) {
    let res;
    try { res = await transport({ client_id: clientId, ...params }); } catch { return { kind: 'lost' }; }
    const body = res?.body;
    if (!res || res.status >= 500 || res.status === 429 || !body || typeof body !== 'object') return { kind: 'lost' };
    if (res.status === 200) return isComplete(body) ? { kind: 'ok', body } : { kind: 'lost' };
    if (TERMINAL.has(body.error)) return { kind: 'terminal', body };
    if (body.error === 'duplicate_request') return { kind: 'duplicate', body };
    if (typeof body.error === 'string') return { kind: 'rejected', body };   // any other OAuth error: definitive
    return { kind: 'lost' };
  }

  // Code exchange: commit to the first verifier. Not retryable once the AS has redeemed the code.
  const exchangeCode = (code, codeVerifier, redirectUri) => lock(async () => {
    const v = random();
    const state = { setup: { code, codeVerifier, redirectUri, v }, grant: null };
    await store.save(state);
    await hook('setup:saved');
    return finishSetup(state);
  });

  const resumeSetup = () => lock(async () => {
    const state = await store.load();
    return state?.setup ? finishSetup(state) : null;
  });

  async function finishSetup(state) {
    const { code, codeVerifier, redirectUri, v } = state.setup;
    const refresh_challenge = await H(v);
    for (let i = 0; i < maxAttempts; i++) {
      if (i) await sleep(Math.min(100 * 2 ** i, 5000));
      const r = await attempt(
        { grant_type: 'authorization_code', code, code_verifier: codeVerifier, redirect_uri: redirectUri, refresh_challenge },
        (b) => typeof b.refresh_token === 'string' && b.refresh_token.length > 0 && typeof b.access_token === 'string');
      if (r.kind === 'lost' || r.kind === 'duplicate') continue;
      if (r.kind === 'rejected') throw new RequestError(r.body.error);
      if (r.kind === 'terminal') {
        state.setup = null;
        await store.save(state);
        throw new TerminalError(r.body.error);
      }
      state.grant = { refresh_token: r.body.refresh_token, n: 1, v, next: null };
      state.setup = null;
      await store.save(state);
      return r.body.access_token;
    }
    throw new TransientError('setup not completed; call resumeSetup() later');
  }

  const refresh = () => lock(async () => {
    const state = await store.load();
    if (!state?.grant) throw new TerminalError('no grant');
    const g = state.grant;
    for (let i = 0; i < maxAttempts; i++) {
      if (!g.next) {
        g.next = random();
        await store.save(state);            // durable before its hash goes on the wire
      }
      await hook('refresh:pending-saved');
      const r = await attempt(
        { grant_type: 'refresh_token', refresh_token: g.refresh_token, refresh_counter: String(g.n), refresh_verifier: g.v, refresh_challenge: await H(g.next) },
        (b) => typeof b.access_token === 'string');

      if (r.kind === 'lost') { await sleep(Math.min(100 * 2 ** i, 5000)); continue; }  // resend identical
      if (r.kind === 'rejected') throw new RequestError(r.body.error);                 // keep state, stop resending
      if (r.kind === 'terminal') {
        state.grant = null;
        await store.save(state);
        throw new TerminalError(r.body.error);
      }
      await hook('refresh:response');
      g.n += 1;                             // the AS now holds H(next) as current
      g.v = g.next;
      g.next = null;
      await store.save(state);
      if (r.kind === 'ok') return r.body.access_token;
      // duplicate: the AS already accepted this request and that response was lost. Go again.
    }
    throw new TransientError('refresh not completed; call refresh() later');
  });

  return { exchangeCode, resumeSetup, refresh };
}
