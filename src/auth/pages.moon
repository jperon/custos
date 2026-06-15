-- src/auth/pages.moon
-- Constructeurs de pages HTML du portail captif.
-- Séparé de server.moon pour permettre les tests unitaires.

H = require "auth.html"

css_content = [[
  * {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
  }

  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    line-height: 1.5;
    color: #333;
    background-color: #f5f5f5;
    padding: 1rem;
    max-width: 1200px;
    margin: 0 auto;
  }

  form {
    background: white;
    padding: 2rem;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    margin: 1rem 0;
  }

  label {
    display: block;
    margin-bottom: 0.5rem;
    font-weight: 500;
  }

  input[type="text"],
  input[type="password"] {
    width: 100%;
    padding: 0.75rem;
    border: 1px solid #ddd;
    border-radius: 4px;
    font-size: 1rem;
    margin-bottom: 1rem;
  }

  button {
    background-color: #007bff;
    color: white;
    border: none;
    padding: 0.75rem 1.5rem;
    border-radius: 4px;
    font-size: 1rem;
    cursor: pointer;
    transition: background-color 0.2s;
  }

  button:hover { background-color: #0056b3; }

  p { margin: 1rem 0; }

  a {
    color: #007bff;
    text-decoration: none;
  }

  a:hover { text-decoration: underline; }

  #refusals {
    background: white;
    padding: 1rem 2rem;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    margin: 1rem 0;
  }

  #refusals h2 {
    font-size: 1rem;
    margin-bottom: 0.5rem;
  }

  #refusals-list {
    list-style: none;
    max-height: 14rem;
    overflow-y: auto;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 0.85rem;
    border: 1px solid #eee;
    border-radius: 4px;
  }

  #refusals-list li {
    padding: 0.3rem 0.6rem;
    border-bottom: 1px solid #f0f0f0;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  #refusals-list li:last-child { border-bottom: none; }

  #refusals-empty { color: #888; }

  @media (max-width: 768px) {
    body { padding: 0.5rem; }
    form { padding: 1rem; }
  }

  @media (max-width: 480px) {
    body { padding: 0.25rem; }
    form { padding: 0.75rem; }
  }
  ]]

page = =>
  "<!DOCTYPE html>\n" .. H.html {lang: "fr",
    H.head {
      H.meta charset: "UTF-8",
      H.title "CustosVirginum",
      H.link rel: "icon", href: "data:image/svg+xml,<svg viewBox='0 0 100 100'><text y='75' font-size='75'>✞</text></svg>"
      H.style css_content
    }
    H.body @
  }

--- Construit la page de succès après connexion.
-- @tparam table       auth_cfg    Configuration auth (heartbeat_interval, idle_timeout).
-- @tparam number      created_at  Timestamp Unix de création de session.
-- @tparam boolean     is_admin    Si vrai, affiche un lien vers /admin.
-- @treturn string HTML de la page.
success_page = (auth_cfg, created_at, is_admin) ->
  interval = tonumber(auth_cfg and auth_cfg.heartbeat_interval) or 30
  interval = 30 if interval <= 0
  refusals_interval = tonumber(auth_cfg and auth_cfg.refusals_poll_interval) or 5
  refusals_interval = 5 if refusals_interval <= 0
  idle_timeout = tonumber(auth_cfg and auth_cfg.idle_timeout) or 300
  session_start = tonumber(created_at) or 0
  admin_link = if is_admin
    H.p H.a { href: "/admin", target: "_blank", rel: "noopener" }, "Administration"
  else
    ""
  page {
    H.p "Connexion réussie. Votre accès est actif tant que cette fenêtre est ouverte."
    H.p { id: "session-timer" }, "Session ouverte depuis : --"
    admin_link
    H.p H.a { href: "/logout" }, "Déconnexion"
    H.div { id: "refusals" },
      H.h2 "Domaines bloqués récemment"
      H.ul { id: "refusals-list" },
        H.li { id: "refusals-empty" }, "Aucun domaine bloqué pour le moment."
    H.script "
      var refusalsIv = #{refusals_interval} * 1000;
      function renderRefusals(items){
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
      function refreshRefusals(){
        fetch('/refusals',{method:'GET',credentials:'same-origin'})
          .then(function(r){ return r.ok ? r.json() : null; })
          .then(function(items){ if (items) renderRefusals(items); })
          .catch(function(){});
      }
      refreshRefusals();
      setInterval(refreshRefusals, refusalsIv);
    "
    H.script "
      var iv = #{interval} * 1000;
      var idle = #{idle_timeout} * 1000;
      var sessionStart = #{session_start};
      var workerJs = \"self.onmessage = function(e) { \
        if (e.data.type === 'start') { \
          setInterval(function() { self.postMessage({type: 'tick'}); }, e.data.interval); \
          setTimeout(function() { self.postMessage({type: 'tick'}); }, 3000); \
        } \
        if (e.data.type === 'visible') { self.postMessage({type: 'tick'}); } \
      }\";
      var worker = new Worker(URL.createObjectURL(new Blob([workerJs], {type: 'application/javascript'})));
      var lastSuccess = Date.now();
      var unauthorized = 0;
      function ping(){
        fetch('/ping',{method:'GET',credentials:'same-origin'})
          .then(function(r){
            if(r.status===401){
              // Un 401 isolé peut venir d'un ping retardé par le navigateur :
              // confirmer par un second ping avant d'alerter.
              unauthorized++;
              if(unauthorized < 2){ setTimeout(ping, 2000); return; }
              if(document.visibilityState==='visible')
                alert('Connexion perdue, veuillez vous authentifier de nouveau.');
              location.href='/';
              return;
            }
            unauthorized = 0;
            lastSuccess = Date.now();
          })
          .catch(function(){
            if (Date.now() - lastSuccess > idle) {
              if (document.visibilityState === 'visible') location.href='/';
            }
          });
      }
      worker.onmessage = function(e) {
        if (e.data.type === 'tick') ping();
      };
      worker.postMessage({type: 'start', interval: iv});
      function updateTimer(){
        var now = Math.floor(Date.now() / 1000);
        var elapsed = now - sessionStart;
        if (elapsed < 0) elapsed = 0;
        var h = Math.floor(elapsed / 3600);
        var m = Math.floor((elapsed % 3600) / 60);
        var txt;
        if (h > 0) {
          txt = h + 'h ' + (m < 10 ? '0' : '') + m + 'min';
        } else {
          txt = m + ' min';
        }
        var el = document.getElementById('session-timer');
        if (el) el.textContent = 'Session ouverte depuis : ' + txt;
      }
      setInterval(updateTimer, 10000);
      updateTimer();
      document.addEventListener('visibilitychange', function(){
        if (document.visibilityState === 'visible') worker.postMessage({type: 'visible'});
      });
      // pagehide se déclenche aussi sur reload/navigation : ne PAS détruire la
      // session ici (/logout), seulement raccourcir son expiration (/bye).
      function bye(){
        if (navigator.sendBeacon) {
          navigator.sendBeacon('/bye');
        } else {
          fetch('/bye', {method:'POST', keepalive:true, credentials:'same-origin'});
        }
      }
      window.addEventListener('pagehide', function(e){
        if (!e.persisted) bye();
      });
    "
  }

{ :page, :success_page, :css_content }
