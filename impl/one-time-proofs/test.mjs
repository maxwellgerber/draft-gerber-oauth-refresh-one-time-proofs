// One-time refresh proofs (signed counter + nonce): client against AS over real HTTP on localhost,
// with injected faults, client crashes and attacker scenarios. KNOWN tests pin down a stated limitation.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createAS, listen } from './server.mjs';
import { createClient, pkcePair, chooseAlg, ALGS, TerminalError, TransientError } from './client.mjs';

const clone = (v) => v === null || typeof v !== 'object' || v instanceof CryptoKey ? v
  : Array.isArray(v) ? v.map(clone) : Object.fromEntries(Object.entries(v).map(([k, x]) => [k, clone(x)]));
class MemStore { data = undefined; load() { return clone(this.data); } save(s) { this.data = clone(s); } }
const makeLock = () => { let tail = Promise.resolve(); return (fn) => { const r = tail.then(fn); tail = r.catch(() => {}); return r; }; };
const noLock = (fn) => fn();
class Crash extends Error {}

const MODES = {
  'drop-request': { processed: false }, 'drop-response': { processed: true },
  '502-before': { processed: false }, '502-after': { processed: true },
  'garbage-200': { processed: true }, 'empty-200': { processed: true }, 'mangled-200': { processed: true },
  '429': { processed: false }, 'waf-403': { processed: false },
  'duplicate-delivery': { processed: true }, 'delay': { processed: false },
};
const MODE_NAMES = Object.keys(MODES);

function makeNet(url) {
  const net = { url, log: [], delayed: [], calls: 0, plan: () => 'ok' };
  net.send = async (params) => {
    const res = await fetch(url + '/token', { method: 'POST', body: new URLSearchParams(params) });
    const text = await res.text();
    let body; try { body = JSON.parse(text); } catch {}
    return { status: res.status, body };
  };
  net.transport = async (params) => {
    const mode = net.plan(net.calls++, params) ?? 'ok';
    net.log.push({ params: { ...params }, mode });
    switch (mode) {
      case 'ok': return net.send(params);
      case 'drop-request': throw new Error('ECONNRESET');
      case 'drop-response': await net.send(params); throw new Error('ETIMEDOUT');
      case '502-before': return { status: 502 };
      case '502-after': await net.send(params); return { status: 502 };
      case 'garbage-200': await net.send(params); return { status: 200 };
      case 'empty-200': await net.send(params); return { status: 200, body: {} };
      case 'mangled-200': await net.send(params); return { status: 200, body: { access_token: 7, refresh_token: 7 } };
      case '429': return { status: 429, body: { error: 'slow_down' } };
      case 'waf-403': return { status: 403 };
      case 'duplicate-delivery': await net.send(params); return net.send(params);
      case 'delay': net.delayed.push({ ...params }); throw new Error('ETIMEDOUT');
      default: throw new Error('unknown mode ' + mode);
    }
  };
  net.flushDelayed = async () => { const out = []; for (const p of net.delayed.splice(0)) out.push(await net.send(p)); return out; };
  return net;
}

async function world(t, asOpts = {}) {
  const as = createAS(asOpts);
  const srv = await listen(as);
  t.after(() => srv.close());
  const net = makeNet(srv.url);
  const newDevice = () => {
    const store = new MemStore(), lock = makeLock();
    const client = (extra = {}) => createClient({ store, lock, transport: net.transport, clientId: 'app', sleep: async () => {}, ...extra });
    return { store, lock, client };
  };
  const login = async (client) => {
    const { verifier, challenge } = await pkcePair();
    return client.exchangeCode(as.authorize(challenge), verifier, 'https://app.example/cb');
  };
  return { as, net, newDevice, login };
}

const isAT = (v) => typeof v === 'string' && v.length >= 40;
const once = (at, mode) => (i) => (i === at ? mode : 'ok');
const crashOnce = (point) => { let done = false; return (p) => { if (p === point && !done) { done = true; throw new Crash(point); } }; };
const rtOf = (store) => store.data.grant.refresh_token;
const inSync = (as, store) => assert.equal(as.grant(rtOf(store)).last, store.data.grant.c, 'AS last == client counter');
const refreshes = (net) => net.log.filter((l) => l.params.grant_type === 'refresh_token');
const signAs = async (grant, c, n) => Buffer.from(await crypto.subtle.sign(ALGS[grant.alg].sign, grant.key, new TextEncoder().encode(`${grant.refresh_token}.${c}.${n}`))).toString('base64url');

// ---- interop, for each algorithm ---------------------------------------------------------------

for (const alg of ['ES256', 'Ed25519']) {
  test(`${alg}: happy path, lost response and recovery; key is non-extractable`, async (t) => {
    const { as, net, newDevice, login } = await world(t);
    const d = newDevice(), c = d.client({ alg });
    assert.ok(isAT(await login(c)));
    assert.equal(JSON.parse(net.log[0].params.refresh_jwk).alg, alg);
    for (let i = 0; i < 3; i++) assert.ok(isAT(await c.refresh()));
    net.plan = once(net.calls, 'drop-response');
    assert.ok(isAT(await c.refresh()));
    inSync(as, d.store);
    assert.equal(as.stats.duplicates, 1);
    assert.equal(as.stats.revocations, 0);
    assert.equal(d.store.data.grant.key.extractable, false);
    await assert.rejects(crypto.subtle.exportKey('pkcs8', d.store.data.grant.key));
  });
}

test('extractability is the client\'s choice and invisible to the AS', async (t) => {
  const { as, newDevice, login } = await world(t);
  const d = newDevice(), c = d.client({ extractable: true });
  await login(c);
  assert.ok(isAT(await c.refresh()));
  assert.ok((await crypto.subtle.exportKey('pkcs8', d.store.data.grant.key)).byteLength > 0);
  assert.equal(as.stats.revocations, 0);
});

test('metadata lists the supported algorithms and the client picks from it', async (t) => {
  const { net } = await world(t, { algs: ['Ed25519'] });
  const md = await (await fetch(net.url + '/.well-known/oauth-authorization-server')).json();
  assert.deepEqual(md.refresh_proof_alg_values_supported, ['Ed25519']);
  assert.equal(chooseAlg(md), 'Ed25519');
  assert.equal(chooseAlg({}), null);
});

test('refresh_jwk validation: unsupported, mismatched, private or malformed keys are rejected without consuming the code', async (t) => {
  const { as, net } = await world(t, { algs: ['ES256'] });
  const ec = await crypto.subtle.exportKey('jwk', (await crypto.subtle.generateKey(ALGS.ES256.generate, true, ['sign'])).publicKey);
  const ecPriv = await crypto.subtle.exportKey('jwk', (await crypto.subtle.generateKey(ALGS.ES256.generate, true, ['sign'])).privateKey);
  const ed = await crypto.subtle.exportKey('jwk', (await crypto.subtle.generateKey(ALGS.Ed25519.generate, true, ['sign'])).publicKey);
  const good = { kty: 'EC', crv: 'P-256', x: ec.x, y: ec.y, alg: 'ES256' };
  const off = Buffer.from(ec.y, 'base64url'); off[31] ^= 1;
  const bad = {
    'missing parameter': undefined,
    'not JSON': 'kty=EC',
    'no alg member': JSON.stringify({ ...good, alg: undefined }),
    'alg the server does not list': JSON.stringify({ kty: 'OKP', crv: 'Ed25519', x: ed.x, alg: 'Ed25519' }),
    'alg does not match key type': JSON.stringify({ kty: 'OKP', crv: 'Ed25519', x: ed.x, alg: 'ES256' }),
    'RSA': JSON.stringify({ kty: 'RSA', n: 'AQAB', e: 'AQAB', alg: 'RS256' }),
    'private key included': JSON.stringify({ ...good, d: ecPriv.d }),
    'point not on curve': JSON.stringify({ ...good, y: off.toString('base64url') }),
    'missing coordinate': JSON.stringify({ ...good, y: undefined }),
  };
  for (const [name, refresh_jwk] of Object.entries(bad)) {
    const { verifier, challenge } = await pkcePair();
    const p = { grant_type: 'authorization_code', client_id: 'app', code: as.authorize(challenge), code_verifier: verifier, redirect_uri: 'https://app.example/cb' };
    if (refresh_jwk !== undefined) p.refresh_jwk = refresh_jwk;
    assert.equal((await net.send(p)).body.error, 'invalid_request', name);
    assert.equal(typeof (await net.send({ ...p, refresh_jwk: JSON.stringify(good) })).body.refresh_token, 'string', name);
  }
});

// ---- faults at refresh -------------------------------------------------------------------------

test('refresh survives every single fault, on the first refresh and mid-stream', async (t) => {
  const { as, net, newDevice, login } = await world(t);
  for (const mode of MODE_NAMES) for (const warmup of [0, 3]) {
    const d = newDevice(), c = d.client();
    await login(c);
    for (let i = 0; i < warmup; i++) await c.refresh();
    net.plan = once(net.calls, mode);
    assert.ok(isAT(await c.refresh()), mode);
    await net.flushDelayed();
    for (let i = 0; i < 3; i++) assert.ok(isAT(await c.refresh()), mode);
    inSync(as, d.store);
  }
  assert.equal(as.stats.revocations, 0);
});

test('every ordered pair of consecutive faults at refresh, stalled requests included', async (t) => {
  const { as, net, newDevice, login } = await world(t);
  let cases = 0;
  for (const a of MODE_NAMES) for (const b of MODE_NAMES) {
    const d = newDevice(), c = d.client();
    await login(c);
    const base = net.calls;
    net.plan = (i) => (i === base ? a : i === base + 1 ? b : 'ok');
    assert.ok(isAT(await c.refresh()), `${a},${b}`);
    assert.ok(isAT(await c.refresh()), `${a},${b}`);
    await net.flushDelayed();                 // stalled copies land after TWO further accepted counters
    assert.ok(isAT(await c.refresh()), `${a},${b}`);
    inSync(as, d.store);
    cases++;
  }
  assert.equal(as.stats.revocations, 0);
  t.diagnostic(`${cases} fault pairs`);
});

test('client crash at each persistence boundary, alone and after each fault', async (t) => {
  const { as, net, newDevice, login } = await world(t);
  let cases = 0;
  for (const point of ['refresh:pending-saved', 'refresh:response']) for (const mode of ['ok', ...MODE_NAMES]) {
    const d = newDevice();
    await login(d.client());
    net.plan = once(net.calls, mode);
    await assert.rejects(d.client({ hook: crashOnce(point) }).refresh(), Crash, `${point} after ${mode}`);
    const reborn = d.client();
    assert.ok(isAT(await reborn.refresh()), `${point} after ${mode}`);
    await net.flushDelayed();
    assert.ok(isAT(await reborn.refresh()), `${point} after ${mode}`);
    inSync(as, d.store);
    cases++;
  }
  assert.equal(as.stats.revocations, 0);
  t.diagnostic(`${cases} crash cases`);
});

function mulberry32(a) { return () => { a |= 0; a = (a + 0x6d2b79f5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }

async function soak(t, { seed, history, flush, faultRate = 0.4, total = 1500 }) {
  const { as, net, newDevice, login } = await world(t, { history });
  const rnd = mulberry32(seed);
  const pick = (xs) => xs[Math.floor(rnd() * xs.length)];
  const d = newDevice();
  const plan = () => (rnd() < faultRate ? pick(MODE_NAMES) : 'ok');
  const relogin = async () => { net.plan = () => 'ok'; await login(d.client()); net.plan = plan; };
  await relogin();
  const flaky = () => d.client({ hook: () => { if (rnd() < 0.03) throw new Crash(); } });
  let client = flaky(), tokens = 0, crashes = 0, lockouts = 0;
  while (tokens < total) {
    try { assert.ok(isAT(await client.refresh())); tokens++; }
    catch (e) {
      if (e instanceof Crash) { crashes++; client = flaky(); }
      else if (e instanceof TerminalError) { lockouts++; net.delayed.length = 0; await relogin(); }
      else if (!(e instanceof TransientError)) throw e;
    }
    if (rnd() < flush) await net.flushDelayed();
  }
  return { exchanges: net.calls, faults: net.log.filter((l) => l.mode !== 'ok').length, crashes, lockouts, duplicates: as.stats.duplicates, badProofs: as.stats.badProofs };
}

for (const seed of [1, 2, 3, 4]) {
  test(`soak seed ${seed}: 1500 refreshes, 40% faulted, crashes, stalled requests landing before the next refresh`, async (t) => {
    const r = await soak(t, { seed, history: 8, flush: 1 });
    assert.equal(r.lockouts, 0);
    assert.equal(r.badProofs, 0);
    t.diagnostic(JSON.stringify(r));
  });
}

test('MEASURE: lockouts when stalled requests can outlive several refreshes, by retention depth', async (t) => {
  for (const [history, flush] of [[1, 0.5], [2, 0.5], [8, 0.5], [8, 0.2], [64, 0.2], [64, 0.05]]) {
    let lockouts = 0;
    for (const seed of [1, 2, 3, 4]) lockouts += (await soak(t, { seed, history, flush })).lockouts;
    t.diagnostic(`retain ${String(history).padStart(2)} pairs, stalls delivered with probability ${flush} per refresh: ${lockouts} lockouts in 6000 refreshes`);
  }
});

test('KNOWN: a stalled request that arrives after its pair has been discarded revokes the grant', async (t) => {
  const { as, net, newDevice, login } = await world(t, { history: 2 });
  const d = newDevice(), c = d.client();
  await login(c);
  net.plan = once(net.calls, 'delay');
  for (let i = 0; i < 3; i++) await c.refresh();     // counters 1..3; pair for 1 is discarded
  await net.flushDelayed();
  assert.equal(as.stats.revocations, 1);
  await assert.rejects(c.refresh(), TerminalError);
});

// ---- the code exchange ---------------------------------------------------------------------------

test('code exchange: faults before the AS sees the request are retried; faults after it require re-authorization', async (t) => {
  const { net, newDevice, login } = await world(t);
  for (const mode of MODE_NAMES) {
    const d = newDevice(), c = d.client();
    net.plan = once(net.calls, mode);
    if (MODES[mode].processed) await assert.rejects(login(c), TerminalError, mode);
    else { assert.ok(isAT(await login(c)), mode); net.delayed.length = 0; assert.ok(isAT(await c.refresh()), mode); }
  }
});

// ---- attacker with captured requests ---------------------------------------------------------------

test('replaying every retained captured refresh yields no token and no revocation', async (t) => {
  const { as, net, newDevice, login } = await world(t);
  const d = newDevice(), c = d.client();
  await login(c);
  for (let i = 0; i < 6; i++) await c.refresh();
  const before = as.stats.accessTokens;
  for (const { params } of refreshes(net)) for (let i = 0; i < 2; i++) assert.equal((await net.send(params)).body.error, 'duplicate_request');
  assert.equal(as.stats.accessTokens, before);
  assert.equal(as.stats.revocations, 0);
  assert.ok(isAT(await c.refresh()));
});

test('forged, recombined or malformed proofs are rejected without revocation', async (t) => {
  const { as, net, newDevice, login } = await world(t);
  const d = newDevice(), c = d.client();
  await login(c);
  await c.refresh();
  const g = d.store.data.grant, cap = refreshes(net).at(-1).params;
  const other = { ...g, key: (await crypto.subtle.generateKey(ALGS.ES256.generate, false, ['sign'])).privateKey };
  const nn = 'B'.repeat(22);
  const raw = Buffer.from(await signAs(g, 2, nn), 'base64url');
  const int = (b) => { let i = 0; while (i < 31 && b[i] === 0) i++; b = b.subarray(i); if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]); return Buffer.concat([Buffer.from([2, b.length]), b]); };
  const body = Buffer.concat([int(raw.subarray(0, 32)), int(raw.subarray(32))]);
  const der = Buffer.concat([Buffer.from([0x30, body.length]), body]).toString('base64url');
  const next = { ...cap, refresh_counter: '2', refresh_nonce: nn };
  for (const p of [
    { ...cap, refresh_counter: '2' },                          // next counter, old proof
    { ...cap, refresh_nonce: nn },                             // new nonce, old proof
    { ...next, refresh_proof: 'A'.repeat(86) },                // guessed proof
    { ...next, refresh_proof: await signAs(other, 2, nn) },    // wrong key
    { ...next, refresh_proof: der },                           // DER instead of the JWS encoding
    { ...cap, refresh_counter: '02' }, { ...cap, refresh_counter: '1e0' }, { ...cap, refresh_counter: '-1' },
    { ...cap, refresh_nonce: 'short' }, { ...cap, refresh_proof: '' },
    { grant_type: 'refresh_token', refresh_token: cap.refresh_token },   // bearer use of the token
  ]) {
    const r = await net.send(p);
    assert.equal(r.status, 400);
    assert.equal(r.body.access_token, undefined);
  }
  assert.equal(as.stats.revocations, 0);
  assert.ok(isAT(await c.refresh()));
});

test('a malleated ES256 signature on a captured request is still just a duplicate', async (t) => {
  const { as, net, newDevice, login } = await world(t);
  const d = newDevice(), c = d.client();
  await login(c);
  await c.refresh();
  const cap = refreshes(net).at(-1).params;
  const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  const sig = Buffer.from(cap.refresh_proof, 'base64url');
  const s2 = (N - BigInt('0x' + sig.subarray(32).toString('hex'))).toString(16).padStart(64, '0');
  const twin = Buffer.concat([sig.subarray(0, 32), Buffer.from(s2, 'hex')]).toString('base64url');
  assert.equal((await net.send({ ...cap, refresh_proof: twin })).body.error, 'duplicate_request');
  assert.equal(as.stats.badProofs, 0);
  assert.equal(as.stats.revocations, 0);
});

test('KNOWN: intercept-and-block yields one access token; the client is told duplicate and carries on', async (t) => {
  const { as, net, newDevice, login } = await world(t);
  const d = newDevice();
  await login(d.client());
  net.plan = once(net.calls, 'delay');
  await assert.rejects(d.client({ maxAttempts: 1 }).refresh(), TransientError);
  const [loot] = await net.flushDelayed();
  assert.ok(isAT(loot.body.access_token));
  assert.ok(isAT(await d.client().refresh()));
  assert.equal(as.stats.revocations, 0);
});

test('authorization-code replay revokes the grant', async (t) => {
  const { as, net, newDevice, login } = await world(t);
  const d = newDevice(), c = d.client();
  await login(c);
  assert.equal((await net.send(net.log[0].params)).body.error, 'invalid_grant');
  assert.equal(as.stats.revocations, 1);
});

// ---- a second key holder (extractable key copied, or attacker driving the key handle) ----------------

async function clonePattern(t, pattern, { history = 8, pending = false } = {}) {
  // pattern: 'T' = thief refreshes, 'V' = victim refreshes, in order.
  const { as, net, newDevice, login } = await world(t, { history });
  const victim = newDevice(), v = victim.client();
  await login(v);
  await v.refresh();
  if (pending) {
    net.plan = once(net.calls, 'drop-request');
    await assert.rejects(victim.client({ maxAttempts: 1 }).refresh(), TransientError);
    assert.ok(victim.store.data.grant.pending);
  }
  const thief = newDevice();
  thief.store.data = clone(victim.store.data);
  const th = thief.client();
  const out = [];
  for (const who of pattern) {
    try { await (who === 'T' ? th : v).refresh(); out.push(who + ':ok'); }
    catch (e) { out.push(who + ':' + (e instanceof TerminalError ? 'REVOKED' : 'err')); break; }
  }
  return { revocations: as.stats.revocations, trace: out.join(' ') };
}
test('second key holder: thief refreshes once, victim\'s next refresh revokes', async (t) => {
  assert.deepEqual(await clonePattern(t, 'TV'), { revocations: 1, trace: 'T:ok V:REVOKED' });
});
test('second key holder: victim refreshes once, thief\'s first refresh revokes', async (t) => {
  assert.deepEqual(await clonePattern(t, 'VT'), { revocations: 1, trace: 'V:ok T:REVOKED' });
});
test('second key holder 30 refreshes ahead, far beyond the retained pairs, is still caught', async (t) => {
  const r = await clonePattern(t, 'T'.repeat(30) + 'V', { history: 2 });
  assert.equal(r.revocations, 1);
  assert.match(r.trace, /V:REVOKED$/);
});
test('second key holder 30 refreshes behind is caught on its first attempt', async (t) => {
  const r = await clonePattern(t, 'V'.repeat(30) + 'T', { history: 2 });
  assert.equal(r.revocations, 1);
  assert.match(r.trace, /T:REVOKED$/);
});
test('KNOWN: a copy taken while an attempt is pending is caught one refresh later', async (t) => {
  assert.deepEqual(await clonePattern(t, 'TVT', { pending: true }), { revocations: 1, trace: 'T:ok V:ok T:REVOKED' });
});

test('proofs pre-signed by an attacker inside the client cannot be used quietly afterwards', async (t) => {
  const { as, net, newDevice, login } = await world(t);
  const d = newDevice(), c = d.client();
  await login(c);
  await c.refresh();
  const g = d.store.data.grant;
  // While inside, the attacker asks the non-extractable key to sign the next five counters.
  const stash = [];
  for (let k = 1; k <= 5; k++) { const n = ('attacker' + k).padEnd(22, 'x'); stash.push({ grant_type: 'refresh_token', client_id: 'app', refresh_token: g.refresh_token, refresh_counter: String(g.c + k), refresh_nonce: n, refresh_proof: await signAs(g, g.c + k, n) }); }
  // Case 1: the victim refreshes first; the attacker's stashed proof for that counter conflicts.
  assert.ok(isAT(await c.refresh()));
  assert.equal((await net.send(stash[0])).body.error, 'invalid_grant');
  assert.equal(as.stats.revocations, 1);
});
test('pre-signed proofs used before the victim returns are caught when it does', async (t) => {
  const { as, net, newDevice, login } = await world(t);
  const d = newDevice(), c = d.client();
  await login(c);
  const g = d.store.data.grant;
  const n = 'attacker-nonce-xxxxxxx';
  const stolen = { grant_type: 'refresh_token', client_id: 'app', refresh_token: g.refresh_token, refresh_counter: '1', refresh_nonce: n, refresh_proof: await signAs(g, 1, n) };
  assert.ok(isAT((await net.send(stolen)).body.access_token));
  await assert.rejects(c.refresh(), TerminalError);
  assert.equal(as.stats.revocations, 1);
});

// ---- concurrency ----------------------------------------------------------------------------------------

test('50 concurrent refreshes across 5 tabs sharing a lock all succeed', async (t) => {
  const { as, newDevice, login } = await world(t);
  const d = newDevice();
  await login(d.client());
  const tabs = Array.from({ length: 5 }, () => d.client());
  const out = await Promise.all(Array.from({ length: 50 }, (_, i) => tabs[i % 5].refresh()));
  assert.ok(out.every(isAT));
  assert.equal(new Set(out).size, 50);
  assert.equal(as.stats.revocations, 0);
});

test('KNOWN: two contexts refreshing WITHOUT a shared lock revoke the grant', async (t) => {
  const { as, newDevice, login } = await world(t);
  const d = newDevice();
  await login(d.client());
  const res = await Promise.allSettled([d.client({ lock: noLock }).refresh(), d.client({ lock: noLock }).refresh()]);
  assert.equal(as.stats.revocations, 1);
  assert.ok(res.some((r) => r.status === 'rejected'));
});
