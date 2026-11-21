// Authorization server: key-bound, non-rotating refresh tokens with a signed counter and nonce.
//
//   refresh_jwk   = client's public key as a JWK with a required "alg" member (code exchange)
//   refresh_proof = signature, in the JWS encoding for that alg, over
//                   refresh_token "." refresh_counter "." refresh_nonce
//
// Per grant the AS keeps the key, the last accepted counter, and recently accepted (counter, nonce) pairs.
// With a valid proof:
//   counter == last + 1            accept, issue access token
//   (counter, nonce) retained      duplicate_request (no token, no change)
//   anything else                  revoke
import http from 'node:http';
import crypto from 'node:crypto';
import { readFile } from 'node:fs/promises';

const b64u = (b) => Buffer.from(b).toString('base64url');
const H = (s) => b64u(crypto.createHash('sha256').update(s).digest());

// alg -> { JWK shape it requires, how to verify a 64-octet signature }
const ALGS = {
  ES256:   { kty: 'EC',  crv: 'P-256',   members: ['x', 'y'], verify: (key, msg, sig) => crypto.verify('sha256', msg, { key, dsaEncoding: 'ieee-p1363' }, sig) },
  Ed25519: { kty: 'OKP', crv: 'Ed25519', members: ['x'],      verify: (key, msg, sig) => crypto.verify(null, msg, key, sig) },
};

export function createAS({ history = 8, algs = ['ES256', 'Ed25519'], codeTtlMs = 60_000, now = () => Date.now() } = {}) {
  const codes = new Map();   // code -> { challenge, expires, refresh_token }
  const grants = new Map();  // refresh_token -> { key, alg, last, seen: Map<counter, nonce>, revoked }
  const stats = { accessTokens: 0, duplicates: 0, revocations: 0, badProofs: 0 };
  const metadata = { issuer: 'https://as.example', token_endpoint: 'https://as.example/token', refresh_proof_alg_values_supported: algs };

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

  function parseKey(text) {
    const jwk = JSON.parse(text);
    const a = ALGS[jwk.alg];
    if (!a || !algs.includes(jwk.alg)) throw new Error('unsupported alg');
    if (jwk.kty !== a.kty || jwk.crv !== a.crv) throw new Error('alg does not match key');
    if ('d' in jwk) throw new Error('private key material');
    const pub = { kty: jwk.kty, crv: jwk.crv };
    for (const m of a.members) { if (typeof jwk[m] !== 'string') throw new Error('missing ' + m); pub[m] = jwk[m]; }
    return { key: crypto.createPublicKey({ format: 'jwk', key: pub }), alg: jwk.alg };   // throws if not a valid point
  }

  function codeExchange(p) {
    const rec = codes.get(p.code);
    if (!rec || rec.expires < now()) return err('invalid_grant');
    if (H(p.code_verifier ?? '') !== rec.challenge) return err('invalid_grant');
    if (rec.refresh_token) {             // code reuse (RFC 6749 section 4.1.2)
      revoke(grants.get(rec.refresh_token));
      return err('invalid_grant');
    }
    let bound;
    try { bound = parseKey(p.refresh_jwk ?? ''); } catch { return err('invalid_request'); }
    const refresh_token = b64u(crypto.randomBytes(32));
    grants.set(refresh_token, { ...bound, last: 0, seen: new Map(), revoked: false });
    rec.refresh_token = refresh_token;
    return ok({ ...accessToken(), refresh_token });
  }

  function refresh(p) {
    const g = grants.get(p.refresh_token);
    if (!g || g.revoked) return err('invalid_grant');
    const c = Number(p.refresh_counter), n = p.refresh_nonce ?? '';
    if (!Number.isSafeInteger(c) || c < 1 || String(c) !== p.refresh_counter ||
        !/^[A-Za-z0-9_-]{16,64}$/.test(n)) return err('invalid_request');

    const sig = Buffer.from(p.refresh_proof ?? '', 'base64url');
    let valid = false;
    try { valid = sig.length === 64 && ALGS[g.alg].verify(g.key, Buffer.from(`${p.refresh_token}.${c}.${n}`), sig); } catch {}
    if (!valid) { stats.badProofs++; return err('invalid_grant'); }   // bad proof: reject, never revoke

    if (c === g.last + 1) {
      g.last = c;
      g.seen.set(c, n);
      for (const k of g.seen.keys()) if (k <= c - history) g.seen.delete(k);
      return ok(accessToken());
    }
    if (g.seen.get(c) === n) { stats.duplicates++; return err('duplicate_request'); }
    revoke(g);                           // valid proof, out of sequence: a second key holder
    return err('invalid_grant');
  }

  function token(p) {
    if (p.grant_type === 'authorization_code') return codeExchange(p);
    if (p.grant_type === 'refresh_token') return refresh(p);
    return err('unsupported_grant_type');
  }
  return { authorize, token, stats, metadata, grant: (rt) => grants.get(rt) };
}

export async function listen(as, { port = 0, staticFiles = {} } = {}) {
  const server = http.createServer(async (req, res) => {
    const path = req.url.split('?')[0];
    const json = (status, body) => { res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(body)); };
    if (req.method === 'GET' && path === '/.well-known/oauth-authorization-server') return json(200, as.metadata);
    if (req.method === 'GET' && staticFiles[path]) {
      const [file, type] = staticFiles[path];
      res.writeHead(200, { 'content-type': type });
      return res.end(await readFile(file));
    }
    let raw = '';
    for await (const chunk of req) raw += chunk;
    const p = Object.fromEntries(new URLSearchParams(raw));
    if (req.method === 'POST' && path === '/token') { const r = as.token(p); return json(r.status, r.body); }
    if (req.method === 'POST' && path === '/authorize') return json(200, { code: as.authorize(p.code_challenge) });
    json(404, { error: 'not_found' });
  });
  await new Promise((r) => server.listen(port, '127.0.0.1', r));
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    close: () => new Promise((r) => { server.closeAllConnections(); server.close(r); }),
  };
}
