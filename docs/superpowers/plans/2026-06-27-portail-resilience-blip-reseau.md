# Résilience du portail captif aux blips réseau — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rendre la page de succès du portail captif résiliente aux interruptions
réseau transitoires (pas d'éjection ni d'alerte intempestive, récupération auto) et
corriger le bug « login impossible après déconnexion » (pool de connexions saturé),
sans toucher à la posture de filtrage.

**Architecture:** La logique de connexion (machine à états online/reconnecting/
expired, backoff, abort-timeout, anti-tempête) est extraite dans un module JS pur
`src/auth/portal_client.js`, testable sous Node. Ce fichier est la **source unique**,
embarqué dans `lua/auth/portal_client_js.lua` par un générateur (`tools/embed_js.lua`)
appelé par `make all`, puis injecté inline dans la page de succès par `pages.moon`.
Le wiring navigateur (Web Worker de heartbeat, événements online/offline/visibility,
beacon /bye, bandeau d'état, rendu des refus) vit dans `mountPortalClient`.

**Tech Stack:** MoonScript/LuaJIT (serveur), JavaScript ES5 (client, compat
mini-navigateur captif), Node.js `node:test` (tests JS), Busted (tests Lua).

## Global Constraints

- **Filtrage inchangé** : aucune modification de `token.moon`, `handlers.moon`
  (durées de vie), ni de la config. Sémantique serveur de `/ping`, `/refusals`,
  `/bye` inchangée. (Le seul changement serveur autorisé est l'ajout, si nécessaire,
  d'un require de la chaîne JS embarquée dans `pages.moon`.)
- **JS en ES5** : pas de `let`/`const`/arrow/`async` dans `portal_client.js` — il
  doit tourner dans le mini-navigateur captif (cf. repli JS pur de `CRYPTO_JS`).
- **Source unique JS** : toute la logique vit dans `src/auth/portal_client.js` ;
  `lua/auth/portal_client_js.lua` est **généré**, jamais édité à la main.
- **Pas de dépendance npm** : tests JS via `node:test`/`node:assert` natifs (Node
  ≥ 18 ; dispo en v24 sur la machine de dev). Aucune `package.json`.
- **`alert()` uniquement sur `expired`** (jamais sur blip réseau), suivi d'une
  redirection vers `/` (ramener l'utilisateur au portail au plus tôt).
- **Bandeau d'état permanent** : `online` (vert) / `reconnecting` (orange) /
  `expired` (rouge).
- Tests : `make test` (Busted + JS) à 100 % et tentative `make test-e2e` en fin.

---

### Task 1: Cœur de la machine à états — `createPortalClient` (ping)

**Files:**
- Create: `src/auth/portal_client.js`
- Test: `tests/unit/auth/portal_client.test.js`

**Interfaces:**
- Produces: `createPortalClient(opts) -> { start(), stop(), ping(), onOnline(),
  onOffline(), onVisible(), getState() }`.
  `opts` (toutes injectables pour les tests) :
  - `fetch(url, options) -> Promise` (resolve `{status:Number, ok:Boolean,
    json():Promise}` ; reject sur erreur réseau/abort)
  - `now() -> Number` (ms)
  - `setTimeout(cb, ms) -> handle`, `clearTimeout(handle)`
  - `heartbeatMs`, `refusalsMs`, `idleMs` (Number), `timeoutMs` (Number, défaut 9000)
  - `newAbort() -> { signal, abort() } | null` (null = pas d'AbortController dispo)
  - `ui: { setState(stateString) }`
  - `onRefusals(items)`, `navigate(url)`, `alert(msg)`, `isVisible() -> Boolean`
- États exposés par `getState()` : `"online" | "reconnecting" | "expired"`.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/auth/portal_client.test.js`:

```js
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test tests/unit/auth/portal_client.test.js`
Expected: FAIL — `Cannot find module '.../src/auth/portal_client.js'`.

- [ ] **Step 3: Write minimal implementation**

Create `src/auth/portal_client.js` (ES5) :

```js
'use strict';
function createPortalClient(opts) {
  var fetchFn = opts.fetch;
  var now = opts.now || function () { return Date.now(); };
  var setT = opts.setTimeout;
  var clearT = opts.clearTimeout;
  var heartbeatMs = opts.heartbeatMs;
  var refusalsMs = opts.refusalsMs;
  var timeoutMs = opts.timeoutMs || 9000;
  var newAbort = opts.newAbort || null;
  var ui = opts.ui || {};
  var onRefusals = opts.onRefusals || function () {};
  var navigate = opts.navigate || function () {};
  var alertFn = opts.alert || function () {};
  var isVisible = opts.isVisible || function () { return true; };

  var state = 'online';
  var inflight = false;
  var unauthorized = 0;
  var lastSuccess = now();
  var backoffMs = 0;
  var retryHandle = null;
  var refusalsHandle = null;

  function setState(s) {
    if (state !== s) { state = s; if (ui.setState) ui.setState(s); }
  }
  function scheduleRetry() {
    backoffMs = backoffMs ? Math.min(backoffMs * 2, heartbeatMs) : 2000;
    if (retryHandle) clearT(retryHandle);
    retryHandle = setT(function () { retryHandle = null; ping(); }, backoffMs);
  }
  function bounded(url, onResp) {
    var ab = newAbort ? newAbort() : null;
    var to = ab ? setT(function () { ab.abort(); }, timeoutMs) : null;
    var opt = { method: 'GET', credentials: 'same-origin' };
    if (ab) opt.signal = ab.signal;
    return fetchFn(url, opt).then(function (r) {
      if (to) clearT(to);
      return onResp(r);
    }, function (e) {
      if (to) clearT(to);
      throw e;
    });
  }
  function ping() {
    if (inflight) return;
    inflight = true;
    bounded('/ping', function (r) {
      inflight = false;
      if (r && r.status === 401) {
        unauthorized++;
        if (unauthorized < 2) { setT(ping, 2000); return; }
        setState('expired');
        if (isVisible()) alertFn('Connexion perdue, veuillez vous authentifier de nouveau.');
        navigate('/');
        return;
      }
      unauthorized = 0;
      lastSuccess = now();
      backoffMs = 0;
      if (retryHandle) { clearT(retryHandle); retryHandle = null; }
      setState('online');
    }).catch(function () {
      inflight = false;
      setState('reconnecting');
      scheduleRetry();
    });
  }
  function refusalsTick() {
    if (state === 'online') {
      bounded('/refusals', function (r) {
        return r && r.ok ? r.json() : null;
      }).then(function (items) { if (items) onRefusals(items); }).catch(function () {});
    }
    refusalsHandle = setT(refusalsTick, refusalsMs);
  }
  function start() {
    if (ui.setState) ui.setState(state);
    ping();
    refusalsHandle = setT(refusalsTick, refusalsMs);
  }
  function stop() {
    if (retryHandle) clearT(retryHandle);
    if (refusalsHandle) clearT(refusalsHandle);
  }
  function onOnline() { backoffMs = 0; ping(); }
  function onOffline() { setState('reconnecting'); }
  function onVisible() { ping(); }

  return {
    start: start, stop: stop, ping: ping,
    onOnline: onOnline, onOffline: onOffline, onVisible: onVisible,
    getState: function () { return state; }
  };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { createPortalClient: createPortalClient };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test tests/unit/auth/portal_client.test.js`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add src/auth/portal_client.js tests/unit/auth/portal_client.test.js
git commit -m "feat(portal): cœur machine à états client (ping, backoff, abort)"
```

---

### Task 2: Polling `/refusals` conditionné + événements online/offline/visible

**Files:**
- Modify: `tests/unit/auth/portal_client.test.js` (ajout de cas)
- (Le code de Task 1 couvre déjà ces comportements ; cette tâche les **verrouille
  par des tests** et corrige le code si un test échoue.)

**Interfaces:**
- Consumes: `createPortalClient` (Task 1), méthodes `start`, `onOnline`,
  `onOffline`, `onVisible`.
- Produces: garantie testée que `/refusals` n'est appelé qu'en état `online`, que
  `onOnline` déclenche un ping immédiat, que `onOffline` passe en `reconnecting`.

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/auth/portal_client.test.js`:

```js
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
```

- [ ] **Step 2: Run test to verify behavior**

Run: `node --test tests/unit/auth/portal_client.test.js`
Expected: PASS (9 tests). Si un cas échoue, corriger `src/auth/portal_client.js`
(la logique de Task 1 doit déjà satisfaire ces tests).

- [ ] **Step 3: Commit**

```bash
git add tests/unit/auth/portal_client.test.js
git commit -m "test(portal): refusals conditionné + événements online/offline"
```

---

### Task 3: Wiring navigateur — `mountPortalClient`

**Files:**
- Modify: `src/auth/portal_client.js` (ajout de `mountPortalClient` + export)
- Modify: `tests/unit/auth/portal_client.test.js` (test d'export)

**Interfaces:**
- Produces: `mountPortalClient(cfg) -> client` où
  `cfg = { heartbeatMs, refusalsMs, idleMs, timeoutMs }`. Câble les dépendances
  réelles du navigateur : `window.fetch`, `Date.now`, `window.setTimeout`,
  `AbortController`, bandeau `#conn-status`, liste `#refusals-list`,
  `location.href`, `window.alert`, `document.visibilityState`, Web Worker de
  heartbeat (repli `setInterval`), événements `online`/`offline`/`visibilitychange`/
  `pagehide` (beacon `/bye`).
- Export Node : `module.exports = { createPortalClient, mountPortalClient }`.

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/auth/portal_client.test.js`:

```js
test('mountPortalClient est exporté', function () {
  const mod = require(path.join(__dirname, '..', '..', '..', 'src', 'auth', 'portal_client.js'));
  assert.strictEqual(typeof mod.mountPortalClient, 'function');
  assert.strictEqual(typeof mod.createPortalClient, 'function');
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test tests/unit/auth/portal_client.test.js`
Expected: FAIL — `mountPortalClient` is `undefined`.

- [ ] **Step 3: Write minimal implementation**

In `src/auth/portal_client.js`, before the `module.exports` guard, add:

```js
function mountPortalClient(cfg) {
  var statusEl = document.getElementById('conn-status');
  var labels = {
    online: 'Accès actif',
    reconnecting: 'Reconnexion en cours…',
    expired: 'Session expirée — reconnexion nécessaire'
  };
  function render(s) {
    if (!statusEl) return;
    statusEl.className = 'conn-' + s;
    statusEl.textContent = labels[s] || s;
  }
  function renderRefusals(items) {
    var list = document.getElementById('refusals-list');
    if (!list) return;
    while (list.firstChild) list.removeChild(list.firstChild);
    if (!items || items.length === 0) {
      var empty = document.createElement('li');
      empty.id = 'refusals-empty';
      empty.textContent = 'Aucun domaine bloqué pour le moment.';
      list.appendChild(empty);
      return;
    }
    for (var i = 0; i < items.length; i++) {
      var it = items[i];
      var li = document.createElement('li');
      var txt = it.qname;
      if (it.reason) txt += ' — ' + it.reason;
      if (it.count && it.count > 1) txt += ' (×' + it.count + ')';
      li.textContent = txt;
      list.appendChild(li);
    }
  }
  var client = createPortalClient({
    fetch: function (u, o) { return window.fetch(u, o); },
    now: function () { return Date.now(); },
    setTimeout: function (cb, ms) { return window.setTimeout(cb, ms); },
    clearTimeout: function (h) { window.clearTimeout(h); },
    heartbeatMs: cfg.heartbeatMs, refusalsMs: cfg.refusalsMs,
    idleMs: cfg.idleMs, timeoutMs: cfg.timeoutMs || 9000,
    newAbort: (typeof AbortController !== 'undefined') ? function () {
      var c = new AbortController();
      return { signal: c.signal, abort: function () { c.abort(); } };
    } : null,
    ui: { setState: render },
    onRefusals: renderRefusals,
    navigate: function (u) { location.href = u; },
    alert: function (m) { window.alert(m); },
    isVisible: function () { return document.visibilityState === 'visible'; }
  });
  try {
    var workerJs = "self.onmessage=function(e){if(e.data.type==='start'){setInterval(function(){self.postMessage({type:'tick'});},e.data.interval);setTimeout(function(){self.postMessage({type:'tick'});},3000);}if(e.data.type==='visible'){self.postMessage({type:'tick'});}}";
    var worker = new Worker(URL.createObjectURL(new Blob([workerJs], { type: 'application/javascript' })));
    worker.onmessage = function (e) { if (e.data.type === 'tick') client.ping(); };
    worker.postMessage({ type: 'start', interval: cfg.heartbeatMs });
    document.addEventListener('visibilitychange', function () {
      if (document.visibilityState === 'visible') { worker.postMessage({ type: 'visible' }); client.onVisible(); }
    });
  } catch (err) {
    window.setInterval(function () { client.ping(); }, cfg.heartbeatMs);
    document.addEventListener('visibilitychange', function () {
      if (document.visibilityState === 'visible') client.onVisible();
    });
  }
  window.addEventListener('online', function () { client.onOnline(); });
  window.addEventListener('offline', function () { client.onOffline(); });
  window.addEventListener('pagehide', function (e) {
    if (!e.persisted) {
      if (navigator.sendBeacon) navigator.sendBeacon('/bye');
      else window.fetch('/bye', { method: 'POST', keepalive: true, credentials: 'same-origin' });
    }
  });
  client.start();
  return client;
}
```

And change the export guard to:

```js
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { createPortalClient: createPortalClient, mountPortalClient: mountPortalClient };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test tests/unit/auth/portal_client.test.js`
Expected: PASS (10 tests).

- [ ] **Step 5: Commit**

```bash
git add src/auth/portal_client.js tests/unit/auth/portal_client.test.js
git commit -m "feat(portal): wiring navigateur mountPortalClient (worker, online, /bye)"
```

---

### Task 4: Générateur d'embarquement + câblage Makefile

**Files:**
- Create: `tools/embed_js.lua`
- Modify: `Makefile` (règle de génération, `all`, `test-js`, `test`, `.PHONY`)
- Test: génération vérifiée par chargement LuaJIT + `node --test` via `make test-js`

**Interfaces:**
- Produces: `lua/auth/portal_client_js.lua` — module Lua qui `return` la chaîne JS
  de `src/auth/portal_client.js`. Consommé par `pages.moon` (Task 5) via
  `require "auth.portal_client_js"`.

- [ ] **Step 1: Write the generator**

Create `tools/embed_js.lua`:

```lua
-- tools/embed_js.lua — embarque un fichier JS dans un module Lua qui le retourne.
-- Usage : luajit tools/embed_js.lua <in.js> <out.lua>
-- Choisit un niveau de long-bracket non présent dans le contenu (robuste).
local inp, out = ...
assert(inp and out, "usage: embed_js.lua <in.js> <out.lua>")
local f = assert(io.open(inp, "r"))
local s = f:read("*a")
f:close()
local lvl = 0
while s:find("]" .. string.rep("=", lvl) .. "]", 1, true) do lvl = lvl + 1 end
local eq = string.rep("=", lvl)
local o = assert(io.open(out, "w"))
o:write("-- GENERATED from " .. inp .. " by tools/embed_js.lua — DO NOT EDIT.\n")
o:write("return [" .. eq .. "[\n")
o:write(s)
o:write("\n]" .. eq .. "]\n")
o:close()
```

- [ ] **Step 2: Add the Makefile rule and wiring**

In `Makefile`, after the `AUTH_LUAS` definition (around line 51), add:

```makefile
# JS embarqué du portail (source unique : src/auth/portal_client.js)
GEN_LUAS := $(LUA)/auth/portal_client_js.lua

$(LUA)/auth/portal_client_js.lua: $(SRC)/auth/portal_client.js tools/embed_js.lua
	@mkdir -p $(LUA)/auth
	$(LUAJIT) tools/embed_js.lua $< $@
```

Modify the `all:` target line to add `$(GEN_LUAS)` to its prerequisites:

```makefile
all: $(LUA)/nfq $(LUAS) $(FILTER_LUAS) $(AUTH_LUAS) $(GEN_LUAS) $(IPPARSE_LUAS) $(IPPARSE_STATIC_LUAS) $(MOONSCRIPT_RUNTIME_LUAS) $(SYNC_LUAS) install-owrt.lua .init.lua
```

Add the `test-js` target after `test-unit` (around line 150):

```makefile
# Tests JS du client portail (Node natif, sans dépendance npm)
test-js:
	node --test tests/unit/auth/portal_client.test.js
```

Change the `test:` target line to include `test-js`:

```makefile
test: all compile-specs compile-helpers test-unit test-js
```

Add `test-js` to the `.PHONY` list (the line containing `all clean check test test-unit ...`):

```makefile
.PHONY: all clean check test test-unit test-js test-vm test-openwrt test-e2e test-e2e-rebuild \
```

- [ ] **Step 3: Generate and verify the embedded module loads**

Run:
```bash
make lua/auth/portal_client_js.lua
luajit -e "local s=require('lua.auth.portal_client_js'); assert(type(s)=='string' and s:find('createPortalClient',1,true)); print('OK len='..#s)"
```
Expected: `OK len=<n>` (n > 1000).

- [ ] **Step 4: Verify test-js runs via make**

Run: `make test-js`
Expected: Node test runner PASS (10 tests).

- [ ] **Step 5: Commit (le `lua/` est suivi dans ce dépôt)**

Les artefacts compilés `lua/` sont **versionnés** (vérifié : `git check-ignore
lua/auth/pages.lua` ne matche pas, `lua/auth/pages.lua` est suivi). Le module généré
suit donc la même politique et est **commité** comme les autres :

```bash
git add tools/embed_js.lua Makefile lua/auth/portal_client_js.lua
git commit -m "build(portal): génère lua/auth/portal_client_js.lua + cible test-js"
```

---

### Task 5: Intégration dans `pages.moon` (bandeau, CSS, bootstrap)

**Files:**
- Modify: `src/auth/pages.moon` (CSS du bandeau, `success_page` : div statut,
  remplacement des deux scripts inline par le JS embarqué + bootstrap, conservation
  du minuteur de session)
- Modify: `tests/unit/auth/success_page_spec.moon` (assertions mises à jour)

**Interfaces:**
- Consumes: `require "auth.portal_client_js"` (chaîne JS, Task 4) ;
  `mountPortalClient(cfg)` défini dans cette chaîne.
- Produces: page de succès contenant `#conn-status`, la chaîne `createPortalClient`/
  `mountPortalClient`, et l'appel `mountPortalClient({...})`.

- [ ] **Step 1: Update the failing unit test**

In `tests/unit/auth/success_page_spec.moon`, **replace** the two tests that assert
the old inline markers:

Replace the test `"injecte l'intervalle de poll des refus (défaut 5s)"`:

```moonscript
  it "injecte l'intervalle de poll des refus (défaut 5s)", ->
    html = success_page cfg_base, os.time!, false
    assert.truthy html\find("refusalsMs: 5000", 1, true)
```

Replace the test `"respecte refusals_poll_interval configuré"`:

```moonscript
  it "respecte refusals_poll_interval configuré", ->
    html = success_page { heartbeat_interval: 30, idle_timeout: 90, refusals_poll_interval: 12 }, 0, false
    assert.truthy html\find("refusalsMs: 12000", 1, true)
```

Replace the test `"délègue le ping à un web worker inline"`:

```moonscript
  it "embarque le client portail et l'amorce", ->
    html = success_page cfg_base, os.time!, false
    assert.truthy html\find("createPortalClient", 1, true)
    assert.truthy html\find("mountPortalClient", 1, true)
    assert.truthy html\find("fetch('/ping'", 1, true)

  it "contient le bandeau d'état de connexion", ->
    html = success_page cfg_base, os.time!, false
    assert.truthy html\find("conn-status", 1, true)
```

Update the test `"contient la liste des domaines bloqués récents et son poller"`:

```moonscript
  it "contient la liste des domaines bloqués récents et son poller", ->
    html = success_page cfg_base, os.time!, false
    assert.truthy html\find("refusals-list", 1, true)
    assert.truthy html\find("Domaines bloqués récemment", 1, true)
    assert.truthy html\find("fetch('/refusals'", 1, true)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `make compile-specs && LUA_PATH="tests/helpers/?.lua;tests/?.lua;lua/?.lua;lua/?/init.lua;$HOME/.luarocks/share/lua/5.1/?.lua;;" busted --lua=luajit --helper=tests/helpers/busted_setup.lua tests/unit/auth/success_page_spec.lua`
Expected: FAIL on the new assertions (`createPortalClient`, `conn-status`,
`refusalsMs: 5000` absent).

- [ ] **Step 3: Implement the page changes**

In `src/auth/pages.moon`:

(a) Add the require near the top (after `H = require "auth.html"`):

```moonscript
PORTAL_CLIENT_JS = require "auth.portal_client_js"
```

(b) Add banner CSS inside `css_content` (before the closing `]]`, after the
`#refusals-empty` rule):

```css
  #conn-status {
    padding: 0.4rem 0.8rem;
    border-radius: 6px;
    font-size: 0.9rem;
    font-weight: 500;
    margin: 0.5rem 0;
  }
  .conn-online { background: #e6f4ea; color: #1e7e34; }
  .conn-reconnecting { background: #fff4e5; color: #b35900; }
  .conn-expired { background: #fdecea; color: #b71c1c; }
```

(c) In `success_page`, add the status banner as the first child of the page body
(before the "Connexion réussie" paragraph):

```moonscript
  page {
    H.div { id: "conn-status", class: "conn-online" }, "Accès actif"
    H.p "Connexion réussie. Votre accès est actif tant que cette fenêtre est ouverte."
```

(d) **Replace** the two existing `H.script "..."` blocks (the refusals poller and
the ping/worker block) with the embedded client + a bootstrap call, and keep only
the session-timer logic inline. Concretely, replace everything from the first
`H.script "` (refusals) through the end of the second `H.script "` (the
worker/pagehide block) with:

```moonscript
    H.script PORTAL_CLIENT_JS
    H.script "
      mountPortalClient({
        heartbeatMs: #{interval} * 1000,
        refusalsMs: #{refusals_interval} * 1000,
        idleMs: #{idle_timeout} * 1000,
        timeoutMs: 9000
      });
      var sessionStart = #{session_start};
      function updateTimer(){
        var now = Math.floor(Date.now() / 1000);
        var elapsed = now - sessionStart;
        if (elapsed < 0) elapsed = 0;
        var h = Math.floor(elapsed / 3600);
        var m = Math.floor((elapsed % 3600) / 60);
        var txt;
        if (h > 0) { txt = h + 'h ' + (m < 10 ? '0' : '') + m + 'min'; }
        else { txt = m + ' min'; }
        var el = document.getElementById('session-timer');
        if (el) el.textContent = 'Session ouverte depuis : ' + txt;
      }
      setInterval(updateTimer, 10000);
      updateTimer();
    "
  }
```

(Keep the existing `H.p { id: "session-timer" }, ...`, `admin_link`, the password
and logout links, and the `#refusals` div unchanged — only the trailing `<script>`
blocks change.)

- [ ] **Step 4: Compile and run the unit test**

Run:
```bash
make lua/auth/portal_client_js.lua lua/auth/pages.lua compile-specs
LUA_PATH="tests/helpers/?.lua;tests/?.lua;lua/?.lua;lua/?/init.lua;$HOME/.luarocks/share/lua/5.1/?.lua;;" busted --lua=luajit --helper=tests/helpers/busted_setup.lua tests/unit/auth/success_page_spec.lua
```
Expected: PASS (all success_page tests).

- [ ] **Step 5: Commit**

```bash
git add src/auth/pages.moon tests/unit/auth/success_page_spec.moon
git commit -m "feat(portal): bandeau d'état + client résilient dans la page de succès"
```

---

### Task 6: Documentation + vérification complète

**Files:**
- Modify: `AGENTS.md` (nouvelle sous-section « Résilience du portail captif »)
- Modify: `doc/CHEATSHEET.md` (entrée portail si une section existe ; sinon ignorer)
- Verify: `make test`, `make coverage` (ciblé), tentative `make test-e2e`

**Interfaces:**
- Consumes: tout ce qui précède.

- [ ] **Step 1: Document the architecture**

Add to `AGENTS.md`, after the « Interface admin web » section, a new section:

```markdown
## Résilience du portail captif aux blips réseau (`src/auth/portal_client.js`)

La logique de connexion de la **page de succès** (heartbeat `/ping`, polling
`/refusals`, bandeau d'état, beacon `/bye`) vit dans `src/auth/portal_client.js`
(JS pur ES5, **source unique**), embarqué dans `lua/auth/portal_client_js.lua`
(généré par `tools/embed_js.lua` via `make all`, jamais édité à la main) et injecté
inline par `auth.pages.success_page`. Testée sous Node (`tests/unit/auth/portal_client.test.js`,
cible `make test-js`).

- **Machine à états** `online`/`reconnecting`/`expired` (`createPortalClient`) :
  une panne réseau passe en `reconnecting` (backoff 2→4→8 s, plafond
  `heartbeat_interval`) sans jamais éjecter ; seul un **401 confirmé** (2 pings)
  passe en `expired` → `alert()` (si onglet visible) + redirection `/`.
- **Anti-tempête** (corrige aussi le bug « login impossible après déconnexion ») :
  chaque fetch est borné par `AbortController` + timeout (≈ 9 s) pour ne pas laisser
  de socket gelée saturer le pool de connexions du navigateur ; un seul ping en vol ;
  `/refusals` suspendu hors état `online`.
- **Wiring navigateur** (`mountPortalClient`) : heartbeat via Web Worker (non
  throttlé en arrière-plan, repli `setInterval`), événements `online`/`offline`
  (ping immédiat au retour) et `visibilitychange`, beacon `/bye` sur `pagehide`.
- **Filtrage inchangé** : aucune modification des durées token/session/nft ni de la
  sémantique serveur. Voir
  [docs/superpowers/specs/2026-06-27-portail-resilience-blip-reseau-design.md](docs/superpowers/specs/2026-06-27-portail-resilience-blip-reseau-design.md).
```

- [ ] **Step 2: Commit the docs**

```bash
git add AGENTS.md
git commit -m "docs(portal): section résilience aux blips réseau"
```

- [ ] **Step 3: Run the full unit + JS suite**

Run: `make test`
Expected: Busted `0 failures` ET `node --test` PASS. Lire le total ; ne pas
conclure sans l'avoir lu.

- [ ] **Step 4: Run targeted coverage**

Run: `make coverage` puis vérifier dans `tmp/coverage/luacov.report.out` que
`auth/pages.lua` reste couvert. (Le JS est couvert par `make test-js`, hors luacov.)

- [ ] **Step 5: Attempt e2e**

Run: `make test-e2e`
Expected: idéalement `0 failed`. Si le homelab libvirt n'est pas provisionné ou si
des échecs DNS flaky de démarrage apparaissent (cf.
`feedback-e2e-dns-warmup-flaky`), le **signaler** sans le considérer comme une
régression de ce changement (aucun chemin e2e ne dépend du JS client).

- [ ] **Step 6: Final commit (si des ajustements ont été nécessaires)**

```bash
git add -A
git commit -m "chore(portal): ajustements post-vérification"
```

---

## Self-Review

**Spec coverage :**
- Machine à états online/reconnecting/expired → Task 1.
- Backoff, un ping en vol, abort-timeout → Task 1.
- Polling /refusals conditionné, online/offline/visible → Task 2.
- Bandeau permanent + alert sur expired uniquement → Task 3 (render) + Task 5 (CSS/DOM).
- Bug login post-déconnexion (AbortController/timeout) → Task 1 (`bounded`) + Task 3
  (`newAbort` réel) + Task 5 (intégration). Non-régression : couverte par le test
  « fetch gelé → abort » (Task 1) qui prouve qu'aucune socket ne reste > timeout.
- Source unique JS + embarquement → Task 4.
- Intégration page + tests busted → Task 5.
- Doc + suites → Task 6.

**Note sur le scénario e2e offline de la spec :** le dépôt n'ayant pas de harnais
navigateur (décision actée : logique extraite + tests Node), les scénarios offline
de la spec sont réalisés par les tests Node de Task 1–2 (blip < timeout → pas
d'éjection ; abort → reconnecting ; 2×401 → expired/navigate), qui couvrent la même
logique sans navigateur. La non-régression login est garantie par le test
d'abort-timeout. Le scénario navigateur réel reste vérifiable manuellement via le
MCP Playwright si besoin.

**Placeholder scan :** aucun TODO/TBD ; tout le code est fourni.

**Type consistency :** `createPortalClient`/`mountPortalClient` signatures
cohérentes entre Tasks 1, 3, 5 ; `bounded(url, onResp)`, `getState()`, `onOnline/
onOffline/onVisible` stables ; marqueurs busted (`refusalsMs: NNNN`,
`createPortalClient`, `mountPortalClient`, `conn-status`) alignés entre Task 5
(assertions) et le code injecté.
