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
