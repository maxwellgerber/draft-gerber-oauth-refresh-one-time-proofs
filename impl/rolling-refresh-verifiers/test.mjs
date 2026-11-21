// Counted hash chain: client against AS over real HTTP on localhost, with injected faults,
// client crashes and attacker scenarios.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createAS, listen } from './server.mjs';
import { createClient, pkcePair, H, TerminalError, TransientError, RequestError } from './client.mjs';

const clone = (v) => (v === null || typeof v !== 'object' ? v : Array.isArray(v) ? v.map(clone) : Object.fromEntries(Object.entries(v).map(([k, x]) => [k, clone(x)])));
class MemStore { data = undefined; load() { return clone(this.data); } save(s) { this.data = clone(s); } }
const makeLock = () => { let tail = Promise.resolve(); return (fn) => { const r = tail.then(fn); tail = r.catch(() => {}); return r; }; };
const noLock = (fn) => fn();
class Crash extends Error {}

const MODES = {
  'drop-request':       { processed: false },
  'drop-response':      { processed: true },
  '502-before':         { processed: false },
  '502-after':          { processed: true },
  'garbage-200':        { processed: true },
  'empty-200':          { processed: true },
  'mangled-200':        { processed: true },
  '429':                { processed: false },
  'waf-403':            { processed: false },
  'duplicate-delivery': { processed: true },
  'delay':              { processed: false },
};
const MODE_NAMES = Object.keys(MODES);

function makeNet(url) {
  const net = { log: [], delayed: [], calls: 0, plan: () => 'ok' };
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
const inSync = async (as, store) => { const g = store.data.grant, s = as.grant(rtOf(store)); assert.equal(s.n, g.n, 'same step'); assert.equal(s.current, await H(g.v), 'AS current == H(verifier)'); };
const refreshes = (net) => net.log.filter((l) => l.params.grant_type === 'refresh_token');

const V = (s) => s.padEnd(43, 'x');
const req = (rt, n, v, ch) => ({ grant_type: 'refresh_token', client_id: 'app', refresh_token: rt, refresh_counter: String(n), refresh_verifier: v, refresh_challenge: ch });

// ---- basics ---------------------------------------------------------------------------------

test('happy path, lost response and recovery; AS state stays bounded', async (t) => {
  const { as, net, newDevice, login } = await world(t, { history: 1 });
  const d = newDevice(), c = d.client();
  assert.ok(isAT(await login(c)));
  for (let i = 0; i < 5; i++) { assert.ok(isAT(await c.refresh())); await inSync(as, d.store); }
  net.plan = once(net.calls, 'drop-response');
  assert.ok(isAT(await c.refresh()));
  await inSync(as, d.store);
  const g = as.grant(rtOf(d.store));
  assert.equal(g.n, 8);                      // 7 accepted steps
  assert.equal(g.spent.size, 1);             // counter + current challenge + one previous step
  assert.deepEqual({ ...as.stats }, { accessTokens: 8, duplicates: 1, revocations: 0 });
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
    await inSync(as, d.store);
  }
  assert.equal(as.stats.revocations, 0);
});

test('every ordered pair of consecutive faults at refresh', async (t) => {
  const { as, net, newDevice, login } = await world(t);
  let cases = 0;
  for (const a of MODE_NAMES) for (const b of MODE_NAMES) {
    const d = newDevice(), c = d.client();
    await login(c);
    const base = net.calls;
    net.plan = (i) => (i === base ? a : i === base + 1 ? b : 'ok');
    assert.ok(isAT(await c.refresh()), `${a},${b}`);
    await net.flushDelayed();
    assert.ok(isAT(await c.refresh()), `${a},${b}`);
    await inSync(as, d.store);
    cases++;
  }
  assert.equal(as.stats.revocations, 0);
  t.diagnostic(`${cases} fault pairs`);
});

test('client crash at each refresh persistence boundary, alone and after each fault', async (t) => {
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
    await inSync(as, d.store);
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
  return { exchanges: net.calls, faults: net.log.filter((l) => l.mode !== 'ok').length, crashes, lockouts, duplicates: as.stats.duplicates };
}

for (const seed of [1, 2, 3, 4]) {
  test(`soak seed ${seed}: 1500 refreshes, 40% faulted, crashes, stalled requests landing before the next refresh`, async (t) => {
    const r = await soak(t, { seed, history: 8, flush: 1 });
    assert.equal(r.lockouts, 0);
    t.diagnostic(JSON.stringify(r));
  });
}

test('MEASURE: lockouts when stalled requests can outlive several refreshes, by retention depth', async (t) => {
  for (const [history, flush] of [[1, 1], [1, 0.5], [2, 0.5], [8, 0.5], [8, 0.2], [64, 0.2], [64, 0.05]]) {
    let lockouts = 0;
    for (const seed of [1, 2, 3, 4]) lockouts += (await soak(t, { seed, history, flush })).lockouts;
    t.diagnostic(`retain ${String(history).padStart(2)} steps, stalls delivered with probability ${flush} per refresh: ${lockouts} lockouts in 6000 refreshes`);
  }
});

test('KNOWN: a stalled request that arrives after its step has been discarded revokes the grant', async (t) => {
  const { as, net, newDevice, login } = await world(t, { history: 2 });
  const d = newDevice(), c = d.client();
  await login(c);
  net.plan = once(net.calls, 'delay');
  for (let i = 0; i < 3; i++) await c.refresh();
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

test('authorization-code replay revokes the grant', async (t) => {
  const { as, net, newDevice, login } = await world(t);
  const d = newDevice(), c = d.client();
  await login(c);
  assert.equal((await net.send(net.log[0].params)).body.error, 'invalid_grant');
  assert.equal(as.stats.revocations, 1);
});

// ---- captured requests and a leaked refresh token ---------------------------------------------------

test('replaying every retained captured refresh unchanged yields no token and no revocation', async (t) => {
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

test('a captured request replayed after its step is discarded revokes (and yields no token)', async (t) => {
  const { as, net, newDevice, login } = await world(t, { history: 2 });
  const d = newDevice(), c = d.client();
  await login(c);
  for (let i = 0; i < 6; i++) await c.refresh();
  const r = await net.send(refreshes(net)[0].params);
  assert.equal(r.body.access_token, undefined);
  assert.equal(as.stats.revocations, 1);
});

test('any captured request replayed with a different next challenge revokes; a spent verifier is never reusable', async (t) => {
  for (const which of [0, 2, 4]) {
    const { as, net, newDevice, login } = await world(t);
    const d = newDevice(), c = d.client();
    await login(c);
    for (let i = 0; i < 5; i++) await c.refresh();
    const r = await net.send({ ...refreshes(net)[which].params, refresh_challenge: await H("attacker") });
    assert.equal(r.body.access_token, undefined);
    assert.equal(as.stats.revocations, 1, `capture ${which}`);
    await assert.rejects(c.refresh(), TerminalError);
  }
});

test('malformed requests are rejected with invalid_request and change nothing', async (t) => {
  const { as, net, newDevice, login } = await world(t);
  const d = newDevice(), c = d.client();
  await login(c);
  await c.refresh(); await c.refresh();
  const rt = rtOf(d.store), ch = await H('x');
  for (const p of [
    { ...req(rt, 3, V('guess'), ch), refresh_counter: '03' }, { ...req(rt, 3, V('guess'), ch), refresh_counter: '-1' },
    { ...req(rt, 3, 'short', ch) }, { ...req(rt, 3, V('guess'), 'short') }, { ...req(rt, 3, 'x'.repeat(129), ch) },
    { grant_type: 'refresh_token', refresh_token: rt },            // bearer use of the token
  ]) {
    const r = await net.send(p);
    assert.equal(r.body.error, 'invalid_request');
  }
  assert.equal(as.stats.revocations, 0);
  assert.ok(isAT(await c.refresh()));
});

test('refresh token alone: a wrong verifier at the current step revokes the grant', async (t) => {
  for (const guess of ['junk', 'challenge']) {
    const { as, net, newDevice, login } = await world(t);
    const d = newDevice(), c = d.client();
    await login(c);
    await c.refresh(); await c.refresh();
    const v = guess === 'junk' ? V('guess') : refreshes(net).at(-1).params.refresh_challenge;   // a challenge is not its own preimage
    const r = await net.send(req(rtOf(d.store), 3, v, await H('x')));
    assert.equal(r.body.error, 'invalid_grant');
    assert.equal(r.body.access_token, undefined);
    assert.equal(as.stats.revocations, 1, guess);
    await assert.rejects(c.refresh(), TerminalError);
  }
});

test('verifiers of any RFC 7636 length and alphabet are accepted', async (t) => {
  const { as, net } = await world(t);
  const { verifier, challenge } = await pkcePair();
  const vs = ['a'.repeat(43), 'B-._~9'.repeat(12), 'z'.repeat(128)];
  const login = await net.send({ grant_type: 'authorization_code', client_id: 'app', code: as.authorize(challenge), code_verifier: verifier, refresh_challenge: await H(vs[0]) });
  const rt = login.body.refresh_token;
  for (let i = 0; i < 2; i++) assert.ok(isAT((await net.send(req(rt, i + 1, vs[i], await H(vs[i + 1])))).body.access_token));
  assert.equal(as.stats.revocations, 0);
});

test('a definitive error from the AS is surfaced once, not retried, and leaves the grant intact', async (t) => {
  const { as, net, newDevice, login } = await world(t);
  const d = newDevice(), c = d.client();
  await login(c);
  const real = net.send;
  let hits = 0;
  net.send = async (p) => (p.grant_type === 'refresh_token' && hits++ === 0 ? { status: 400, body: { error: 'invalid_scope' } } : real(p));
  await assert.rejects(c.refresh(), RequestError);
  assert.equal(hits, 1);
  assert.ok(isAT(await c.refresh()));             // same pending request goes through afterwards
  assert.equal(as.stats.revocations, 0);
});

test('refresh token alone: any other step number with a junk verifier revokes the grant', async (t) => {
  for (const n of [1, 2, 4, 50]) {       // AS is at step 3
    const { as, net, newDevice, login } = await world(t);
    const d = newDevice(), c = d.client();
    await login(c);
    await c.refresh(); await c.refresh();
    const r = await net.send(req(rtOf(d.store), n, V('junk'), await H('x')));
    assert.equal(r.body.error, 'invalid_grant');
    assert.equal(as.stats.revocations, 1, `n=${n}`);
    await assert.rejects(c.refresh(), TerminalError);
  }
});

test('KNOWN: intercept-and-block, forwarded unchanged, yields one access token; the client is told duplicate and carries on', async (t) => {
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

async function hijack(t, history, attackerRefreshes, clientReturns = true) {
  // The attacker blocks the client's request, substitutes its own next challenge, and carries on the chain.
  const { as, net, newDevice, login } = await world(t, { history });
  const d = newDevice();
  await login(d.client());
  net.plan = once(net.calls, 'delay');
  await assert.rejects(d.client({ maxAttempts: 1 }).refresh(), TransientError);
  const stolen = net.delayed.splice(0)[0];
  const chain = Array.from({ length: attackerRefreshes + 2 }, (_, i) => V('attacker-' + i));
  const n0 = Number(stolen.refresh_counter);
  assert.ok(isAT((await net.send({ ...stolen, refresh_challenge: await H(chain[0]) })).body.access_token));
  for (let i = 0; i < attackerRefreshes; i++)
    assert.ok(isAT((await net.send(req(stolen.refresh_token, n0 + 1 + i, chain[i], await H(chain[i + 1])))).body.access_token));
  if (clientReturns) await assert.rejects(d.client().refresh(), TerminalError);   // client retries its own request
  const k = attackerRefreshes;
  const attackerStillIn = isAT((await net.send(req(stolen.refresh_token, n0 + 1 + k, chain[k], await H(chain[k + 1])))).body.access_token);
  return { revocations: as.stats.revocations, attackerStillIn };
}
for (const k of [0, 1, 2, 30])
  test(`hijacked request, attacker refreshes ${k} more times with one retained step: the client's retry revokes`, async (t) => {
    assert.deepEqual(await hijack(t, 1, k), { revocations: 1, attackerStillIn: false });
  });
test('hijacked request with the response relayed to the client: the client\'s next refresh revokes', async (t) => {
  // The attacker blocks the request, substitutes its own challenge, and hands the 200 back to the client,
  // so the client advances and never retransmits.
  const { as, net, newDevice, login } = await world(t, { history: 1 });
  const d = newDevice(), c = d.client();
  await login(c);
  const real = net.send;
  const mine = [V('attacker-0'), V('attacker-1')];
  let stolen = null;
  net.send = async (p) => {
    if (p.grant_type !== 'refresh_token' || stolen) return real(p);
    stolen = { ...p };
    return real({ ...p, refresh_challenge: await H(mine[0]) });
  };
  assert.ok(isAT(await c.refresh()));             // client believes step 1 went through with its own challenge
  await assert.rejects(c.refresh(), TerminalError);
  assert.equal(as.stats.revocations, 1);
  const r = await real(req(stolen.refresh_token, 2, mine[0], await H(mine[1])));
  assert.equal(r.body.access_token, undefined);   // attacker is out too
});
test('KNOWN: a hijack is not detected if the client never refreshes again', async (t) => {
  assert.deepEqual(await hijack(t, 1, 3, false), { revocations: 0, attackerStillIn: true });
});

// ---- storage theft ------------------------------------------------------------------------------------

async function clonePattern(t, pattern, { history = 8, pending = false } = {}) {
  // pattern: 'T' = thief refreshes, 'V' = victim refreshes, in order.
  const { as, net, newDevice, login } = await world(t, { history });
  const victim = newDevice(), v = victim.client();
  await login(v);
  await v.refresh();
  if (pending) {
    net.plan = once(net.calls, 'drop-request');
    await assert.rejects(victim.client({ maxAttempts: 1 }).refresh(), TransientError);
    assert.ok(victim.store.data.grant.next);
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
test('storage theft: thief refreshes once, victim\'s next refresh revokes', async (t) => {
  assert.deepEqual(await clonePattern(t, 'TV'), { revocations: 1, trace: 'T:ok V:REVOKED' });
});
test('storage theft: victim refreshes once, thief\'s first refresh revokes', async (t) => {
  assert.deepEqual(await clonePattern(t, 'VT'), { revocations: 1, trace: 'V:ok T:REVOKED' });
});
for (const k of [2, 5, 30]) {
  test(`storage theft: thief ${k} refreshes ahead, one retained step: caught when the victim returns`, async (t) => {
    const r = await clonePattern(t, 'T'.repeat(k) + 'V', { history: 1 });
    assert.equal(r.revocations, 1);
    assert.match(r.trace, /V:REVOKED$/);
  });
  test(`storage theft: thief ${k} refreshes behind, one retained step: caught on its first attempt`, async (t) => {
    const r = await clonePattern(t, 'V'.repeat(k) + 'T', { history: 1 });
    assert.equal(r.revocations, 1);
    assert.match(r.trace, /T:REVOKED$/);
  });
}
test('KNOWN: a copy taken while an attempt is pending is caught one refresh later', async (t) => {
  assert.deepEqual(await clonePattern(t, 'TVT', { pending: true }), { revocations: 1, trace: 'T:ok V:ok T:REVOKED' });
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
