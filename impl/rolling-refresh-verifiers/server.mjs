// Authorization server: counted hash chain ("PKCE chaining with a step number").
//
// Per grant the AS keeps:
//   n        the step number of the challenge it holds
//   current  that challenge, = SHA256(verifier_n), the PKCE S256 transform
//   spent    the last `history` accepted steps: n -> { challenge, successor }
//
// Refresh request: refresh_token, refresh_counter (n), refresh_verifier, refresh_challenge (for n+1).
//   n == current step, hash matches          accept
//   n == current step, hash does not match   invalid_grant, no change (sender does not know the verifier)
//   n retained, identical request            duplicate_request (no token, no change)
//   anything else with a valid refresh token revoke: a retained step with different contents,
//                                            an older step, or a step the AS has not reached
import http from 'node:http';
import crypto from 'node:crypto';
import { readFile } from 'node:fs/promises';

const b64u = (b) => Buffer.from(b).toString('base64url');
const H = (s) => b64u(crypto.createHash('sha256').update(s).digest());
const HASH = /^[A-Za-z0-9_-]{43}$/;

export function createAS({ history = 8, codeTtlMs = 60_000, now = () => Date.now() } = {}) {
  const codes = new Map();   // code -> { challenge, expires, refresh_token }
  const grants = new Map();  // refresh_token -> { current, spent: Map<challenge, successor>, revoked }
  const stats = { accessTokens: 0, duplicates: 0, revocations: 0, rejects: 0 };

  const ok = (body) => ({ status: 200, body });
  const err = (error) => ({ status: 400, body: { error } });
  const accessToken = () => {
    stats.accessTokens++;
    return { access_token: b64u(crypto.randomBytes(32)), token_type: 'Bearer', expires_in: 600 };
  };
  const revoke = (g) => { if (g && !g.revoked) { g.revoked = true; stats.revocations++; } };

  function authorize(codeChallenge) {
    const code = b64u(crypto.randomBytes(16));
    codes.set(code, { challenge: codeChallenge, expires: now() + codeTtlMs, refresh_token: null });
    return code;
  }

  function codeExchange(p) {
    const rec = codes.get(p.code);
    if (!rec || rec.expires < now()) return err('invalid_grant');
    if (H(p.code_verifier ?? '') !== rec.challenge) return err('invalid_grant');
    if (rec.refresh_token) {             // code reuse (RFC 6749 section 4.1.2)
      revoke(grants.get(rec.refresh_token));
      return err('invalid_grant');
    }
    if (!HASH.test(p.refresh_challenge ?? '')) return err('invalid_request');
    const refresh_token = b64u(crypto.randomBytes(32));
    grants.set(refresh_token, { n: 1, current: p.refresh_challenge, spent: new Map(), revoked: false });
    rec.refresh_token = refresh_token;
    return ok({ ...accessToken(), refresh_token });
  }

  function refresh(p) {
    const g = grants.get(p.refresh_token);
    if (!g || g.revoked) return err('invalid_grant');
    if (!/^[1-9][0-9]{0,15}$/.test(p.refresh_counter ?? '') || !HASH.test(p.refresh_verifier ?? '') || !HASH.test(p.refresh_challenge ?? ''))
      return err('invalid_request');
    const n = Number(p.refresh_counter);
    const h = H(p.refresh_verifier);

    if (n === g.n) {
      if (h !== g.current) { stats.rejects++; return err('invalid_grant'); }   // no verifier knowledge: no change
      g.spent.set(n, { challenge: g.current, successor: p.refresh_challenge });
      for (const k of g.spent.keys()) if (k <= n - history) g.spent.delete(k);
      g.n = n + 1;
      g.current = p.refresh_challenge;
      return ok(accessToken());
    }
    const s = g.spent.get(n);
    if (s && s.challenge === h && s.successor === p.refresh_challenge) { stats.duplicates++; return err('duplicate_request'); }
    revoke(g);                             // out of sequence: a second holder, or a step no longer retained
    return err('invalid_grant');
  }

  function token(p) {
    if (p.grant_type === 'authorization_code') return codeExchange(p);
    if (p.grant_type === 'refresh_token') return refresh(p);
    return err('unsupported_grant_type');
  }
  return { authorize, token, stats, grant: (rt) => grants.get(rt) };
}

export async function listen(as, { port = 0, staticFiles = {} } = {}) {
  const server = http.createServer(async (req, res) => {
    const path = req.url.split('?')[0];
    if (req.method === 'GET' && staticFiles[path]) {
      const [file, type] = staticFiles[path];
      res.writeHead(200, { 'content-type': type });
      return res.end(await readFile(file));
    }
    let raw = '';
    for await (const chunk of req) raw += chunk;
    const p = Object.fromEntries(new URLSearchParams(raw));
    let r;
    if (req.method === 'POST' && path === '/token') r = as.token(p);
    else if (req.method === 'POST' && path === '/authorize') r = { status: 200, body: { code: as.authorize(p.code_challenge) } };
    else r = { status: 404, body: { error: 'not_found' } };
    res.writeHead(r.status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(JSON.stringify(r.body));
  });
  await new Promise((r) => server.listen(port, '127.0.0.1', r));
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    close: () => new Promise((r) => { server.closeAllConnections(); server.close(r); }),
  };
}
