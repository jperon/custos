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
  var refusalsInflight = false;

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
        if (state === 'expired') return;
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
    if (state === 'online' && !refusalsInflight) {
      refusalsInflight = true;
      bounded('/refusals', function (r) {
        return r && r.ok ? r.json() : null;
      }).then(function (items) {
        refusalsInflight = false;
        if (items) onRefusals(items);
      }).catch(function () { refusalsInflight = false; });
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

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { createPortalClient: createPortalClient, mountPortalClient: mountPortalClient };
}
