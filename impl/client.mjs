// Client core for signed-counter refresh with a per-attempt nonce. Runs unchanged in browsers and Node.
//
// store:     { load(): state|undefined, save(state) }   durable, atomic per save
// lock:      (fn) => runs fn exclusively across every context sharing the store
// transport: (params) => { status, body }  or throws on network failure
//
// Grant state: { refresh_token, key, alg, c, pending }
//   c        the last counter known to be consumed
//   pending  the attempt in progress, { c, n }, saved before it is first sent

const enc = (s) => new TextEncoder().encode(s);
export const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)))
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const random = (n) => b64u(crypto.getRandomValues(new Uint8Array(n)));

export class TerminalError extends Error {}   // grant is gone: restart authorization
export class TransientError extends Error {}  // gave up for now: state intact, call again later

export const ALGS = {
  ES256:   { generate: { name: 'ECDSA', namedCurve: 'P-256' }, sign: { name: 'ECDSA', hash: 'SHA-256' }, members: ['kty', 'crv', 'x', 'y'] },
  Ed25519: { generate: { name: 'Ed25519' },                    sign: { name: 'Ed25519' },                 members: ['kty', 'crv', 'x'] },
};
const TERMINAL = new Set(['invalid_grant', 'invalid_client']);

export async function pkcePair() {
  const verifier = random(32);
  return { verifier, challenge: b64u(await crypto.subtle.digest('SHA-256', enc(verifier))) };
}

// Pick the first algorithm we implement that the server lists; null if the server does not support this.
export function chooseAlg(metadata, preferred = ['ES256', 'Ed25519']) {
  const offered = metadata?.refresh_proof_alg_values_supported;
  return Array.isArray(offered) ? preferred.find((a) => offered.includes(a) && ALGS[a]) ?? null : null;
}

export function createClient({
  store, lock, transport, clientId,
  alg = 'ES256',
  extractable = false,          // private key extractability: false wherever the platform allows it
  maxAttempts = 8,
  sleep = (ms) => new Promise((r) => setTimeout(r, ms)),
  hook = () => {},              // test-only crash points
}) {
  async function attempt(params, isComplete) {
    let res;
    try { res = await transport({ client_id: clientId, ...params }); } catch { return { kind: 'lost' }; }
    const body = res?.body;
    if (!res || res.status >= 500 || !body || typeof body !== 'object') return { kind: 'lost' };
    if (res.status === 200) return isComplete(body) ? { kind: 'ok', body } : { kind: 'lost' };
    if (TERMINAL.has(body.error)) return { kind: 'terminal', body };
    if (body.error === 'duplicate_request') return { kind: 'duplicate', body };
    return { kind: 'lost' };      // 429, intermediary error pages, unknown errors: retry, never drop state
  }

  // Code exchange: registers the public key. Not retryable once the AS has redeemed the code.
  const exchangeCode = (code, codeVerifier, redirectUri) => lock(async () => {
    const kp = await crypto.subtle.generateKey(ALGS[alg].generate, extractable, ['sign']);
    const exported = await crypto.subtle.exportKey('jwk', kp.publicKey);
    const jwk = { alg };
    for (const m of ALGS[alg].members) jwk[m] = exported[m];
    for (let i = 0; i < maxAttempts; i++) {
      if (i) await sleep(Math.min(100 * 2 ** i, 5000));
      const r = await attempt(
        { grant_type: 'authorization_code', code, code_verifier: codeVerifier, redirect_uri: redirectUri, refresh_jwk: JSON.stringify(jwk) },
        (b) => typeof b.refresh_token === 'string' && b.refresh_token.length > 0 && typeof b.access_token === 'string');
      if (r.kind === 'lost' || r.kind === 'duplicate') continue;
      if (r.kind === 'terminal') throw new TerminalError(r.body.error);
      await store.save({ grant: { refresh_token: r.body.refresh_token, key: kp.privateKey, alg, c: 0, pending: null } });
      return r.body.access_token;
    }
    throw new TransientError('code exchange not completed');
  });

  const refresh = () => lock(async () => {
    const state = await store.load();
    if (!state?.grant) throw new TerminalError('no grant');
    const g = state.grant;
    for (let i = 0; i < maxAttempts; i++) {
      if (!g.pending) {
        g.pending = { c: g.c + 1, n: random(16) };
        await store.save(state);            // durable before it goes on the wire
      }
      await hook('refresh:pending-saved');
      const { c, n } = g.pending;
      const proof = b64u(await crypto.subtle.sign(ALGS[g.alg].sign, g.key, enc(`${g.refresh_token}.${c}.${n}`)));
      const r = await attempt(
        { grant_type: 'refresh_token', refresh_token: g.refresh_token, refresh_counter: String(c), refresh_nonce: n, refresh_proof: proof },
        (b) => typeof b.access_token === 'string');

      if (r.kind === 'lost') { await sleep(Math.min(100 * 2 ** i, 5000)); continue; }  // same (c, n) again
      if (r.kind === 'terminal') {
        await store.save({ grant: null });
        throw new TerminalError(r.body.error);
      }
      await hook('refresh:response');
      g.c = c;
      g.pending = null;
      await store.save(state);
      if (r.kind === 'ok') return r.body.access_token;
      // duplicate: the AS already accepted (c, n) and that response was lost. Go again with c + 1.
    }
    throw new TransientError('refresh not completed; call refresh() later');
  });

  return { exchangeCode, refresh };
}
