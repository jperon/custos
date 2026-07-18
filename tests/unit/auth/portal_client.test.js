'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const { createPortalClient } = require(
  path.join(__dirname, '..', '..', '..', 'src', 'auth', 'portal_client.js'));

// Horloge + ordonnanceur déterministes.
function makeClock() {
  let nowMs = 0, id = 0;
  const tasks = new Map();
  return {
    now: function () { return nowMs; },
    setTimeout: function (cb, ms) { const h = ++id; tasks.set(h, { t: nowMs + ms, cb: cb }); return h; },
    clearTimeout: function (h) { tasks.delete(h); },
    advance: async function (ms) {
      const target = nowMs + ms;
      for (let i = 0; i < 8; i++) await Promise.resolve();
      while (true) {
        let next = null;
        for (const [h, task] of tasks) {
          if (task.t <= target && (next === null || task.t < tasks.get(next).t)) next = h;
        }
        if (next === null) break;
        const task = tasks.get(next); tasks.delete(next); nowMs = task.t; task.cb();
        for (let i = 0; i < 8; i++) await Promise.resolve();
      }
      nowMs = target;
      for (let i = 0; i < 8; i++) await Promise.resolve();
    }
  };
}
// AbortController simulé.
function makeAbort() {
  const signal = { aborted: false, onabort: null };
  return { signal: signal, abort: function () { signal.aborted = true; if (signal.onabort) signal.onabort(); } };
}
// Réponses séquentielles ; "net" = rejet réseau, "hang" = jamais résolu (abortable).
function fetchQueue(responses) {
  const calls = [];
  let i = 0;
  const fn = function (url, opt) {
    calls.push({ url: url, opt: opt });
    const r = responses[Math.min(i, responses.length - 1)]; i++;
    if (r === 'net') return Promise.reject(new Error('network'));
    if (r === 'hang') return new Promise(function (_, rej) {
      if (opt && opt.signal) opt.signal.onabort = function () { rej(new Error('AbortError')); };
    });
    return Promise.resolve(r);
  };
  fn.calls = calls;
  return fn;
}
function baseOpts(clock, fetchFn, over) {
  const o = {
    fetch: fetchFn, now: clock.now, setTimeout: clock.setTimeout, clearTimeout: clock.clearTimeout,
    heartbeatMs: 20000, refusalsMs: 5000, idleMs: 90000, timeoutMs: 9000,
    newAbort: makeAbort,
    ui: { setState: function () {} },
    onRefusals: function () {}, navigate: function () {}, alert: function () {},
    isVisible: function () { return true; }
  };
  for (const k in (over || {})) o[k] = over[k];
  return o;
}
function ok204() { return { status: 204, ok: true, json: function () { return Promise.resolve(null); } }; }

test('ping réussi → état online', async function () {
  const clock = makeClock();
  const c = createPortalClient(baseOpts(clock, fetchQueue([ok204()])));
  c.ping();
  await clock.advance(1);
  assert.strictEqual(c.getState(), 'online');
});

test('erreur réseau → reconnecting puis online au retour', async function () {
  const clock = makeClock();
  const fetchFn = fetchQueue(['net', ok204()]);
  const c = createPortalClient(baseOpts(clock, fetchFn));
  c.ping();
  await clock.advance(1);
  assert.strictEqual(c.getState(), 'reconnecting');
  await clock.advance(2000); // backoff initial → 2e tentative réussit
  assert.strictEqual(c.getState(), 'online');
});

test('un seul 401 isolé ne fait pas expirer', async function () {
  const clock = makeClock();
  const navs = [];
  const c = createPortalClient(baseOpts(clock, fetchQueue([
    { status: 401, ok: false, json: function () { return Promise.resolve(null); } }, ok204()
  ]), { navigate: function (u) { navs.push(u); } }));
  c.ping();
  await clock.advance(2000); // re-ping de confirmation à 2s → 204
  assert.strictEqual(c.getState(), 'online');
  assert.deepStrictEqual(navs, []);
});

test('deux 401 consécutifs → expired + alert + navigate', async function () {
  const clock = makeClock();
  const navs = [], alerts = [];
  const r401 = function () { return { status: 401, ok: false, json: function () { return Promise.resolve(null); } }; };
  const c = createPortalClient(baseOpts(clock, fetchQueue([r401(), r401()]), {
    navigate: function (u) { navs.push(u); }, alert: function (m) { alerts.push(m); }
  }));
  c.ping();
  await clock.advance(2000);
  assert.strictEqual(c.getState(), 'expired');
  assert.deepStrictEqual(navs, ['/']);
  assert.strictEqual(alerts.length, 1);
});

test('un ping en 401 après expiration ne re-alerte pas', async function () {
  const clock = makeClock();
  const navs = [], alerts = [];
  const r401 = function () { return { status: 401, ok: false, json: function () { return Promise.resolve(null); } }; };
  const c = createPortalClient(baseOpts(clock, fetchQueue([r401(), r401(), r401()]), {
    navigate: function (u) { navs.push(u); }, alert: function (m) { alerts.push(m); }
  }));
  c.ping();
  await clock.advance(2000);
  assert.strictEqual(c.getState(), 'expired');
  assert.strictEqual(alerts.length, 1);
  c.ping();
  await clock.advance(0);
  assert.strictEqual(alerts.length, 1);
  assert.deepStrictEqual(navs, ['/']);
});

test('garde un seul ping en vol', async function () {
  const clock = makeClock();
  const fetchFn = fetchQueue(['hang']);
  const c = createPortalClient(baseOpts(clock, fetchFn));
  c.ping(); c.ping(); c.ping();
  assert.strictEqual(fetchFn.calls.filter(function (x) { return x.url === '/ping'; }).length, 1);
});

test('fetch gelé → abort après timeout → reconnecting', async function () {
  const clock = makeClock();
  const c = createPortalClient(baseOpts(clock, fetchQueue(['hang'])));
  c.ping();
  await clock.advance(9000);
  assert.strictEqual(c.getState(), 'reconnecting');
});

test('refusals: appelé en online, pas en reconnecting', async function () {
  const clock = makeClock();
  // 1er /ping: net (→ reconnecting). Tous les /refusals suivants: ok liste vide.
  const fetchFn = function (url, opt) {
    fetchFn.calls.push(url);
    if (url === '/ping') return Promise.reject(new Error('network'));
    return Promise.resolve({ status: 200, ok: true, json: function () { return Promise.resolve([]); } });
  };
  fetchFn.calls = [];
  const c = createPortalClient(baseOpts(clock, fetchFn, { heartbeatMs: 20000, refusalsMs: 5000 }));
  c.start();                 // ping (net → reconnecting) + planifie refusalsTick
  await clock.advance(5000); // 1er refusalsTick : état reconnecting → pas de fetch /refusals
  const refCount = fetchFn.calls.filter(function (u) { return u === '/refusals'; }).length;
  assert.strictEqual(c.getState(), 'reconnecting');
  assert.strictEqual(refCount, 0);
});

test('refusals: un seul en vol, pas de chevauchement si réponse lente', async function () {
  const clock = makeClock();
  // /ping toujours ok ; /refusals ne répond jamais avant la fin du test (hang).
  const fetchFn = fetchQueue([ok204(), 'hang']);
  const c = createPortalClient(baseOpts(clock, fetchFn, { heartbeatMs: 20000, refusalsMs: 5000, timeoutMs: 9000 }));
  c.start();
  await clock.advance(5000);  // 1er refusalsTick : lance /refusals (jamais résolu)
  await clock.advance(5000);  // 2e refusalsTick : ne doit PAS relancer /refusals tant que le 1er est en vol
  const refCount = fetchFn.calls.filter(function (x) { return x.url === '/refusals'; }).length;
  assert.strictEqual(refCount, 1);
});

test('onOnline déclenche un ping immédiat', async function () {
  const clock = makeClock();
  const fetchFn = fetchQueue([ok204()]);
  const c = createPortalClient(baseOpts(clock, fetchFn));
  c.onOnline();
  await clock.advance(1);
  assert.strictEqual(fetchFn.calls.filter(function (x) { return x.url === '/ping'; }).length, 1);
  assert.strictEqual(c.getState(), 'online');
});

test('onOffline passe en reconnecting sans fetch', async function () {
  const clock = makeClock();
  const fetchFn = fetchQueue([ok204()]);
  const c = createPortalClient(baseOpts(clock, fetchFn));
  c.onOffline();
  assert.strictEqual(c.getState(), 'reconnecting');
  assert.strictEqual(fetchFn.calls.length, 0);
});

test('mountPortalClient est exporté', function () {
  const mod = require(path.join(__dirname, '..', '..', '..', 'src', 'auth', 'portal_client.js'));
  assert.strictEqual(typeof mod.mountPortalClient, 'function');
  assert.strictEqual(typeof mod.createPortalClient, 'function');
});
