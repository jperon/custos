-- src/auth/pages.moon
-- Constructeurs de pages HTML du portail captif.
-- Séparé de server.moon pour permettre les tests unitaires.

unpack or= table.unpack
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
  idle_timeout = tonumber(auth_cfg and auth_cfg.idle_timeout) or 90
  session_start = tonumber(created_at) or 0
  admin_link = if is_admin
    { H.p H.a { href: "/admin" }, "Administration" }
  else
    {}
  page {
    H.p "Connexion réussie. Votre accès est actif tant que cette fenêtre est ouverte."
    H.p { id: "session-timer" }, "Session ouverte depuis : --"
    unpack admin_link
    H.p H.a { href: "/logout" }, "Déconnexion"
    H.script "
      var iv = #{interval} * 1000;
      var idle = #{idle_timeout} * 1000;
      var sessionStart = #{session_start};
      var lastSuccess = Date.now();
      function ping(){
        fetch('/ping',{method:'GET',credentials:'same-origin'})
          .then(function(r){
            lastSuccess = Date.now();
            if(r.status===401){
              if(document.visibilityState!=='visible')
                alert('Connexion perdue, veuillez vous authentifier de nouveau.');
              location.href='/';
            }
          })
          .catch(function(){
            if (Date.now() - lastSuccess > idle) {
              if (document.visibilityState === 'visible') location.href='/';
            }
          });
      }
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
      setInterval(ping, iv);
      setInterval(updateTimer, 10000);
      setTimeout(ping, 3000);
      updateTimer();
      // Envoyer un ping immédiat au retour en foreground (anti-throttling navigateur).
      document.addEventListener('visibilitychange', function(){
        if (document.visibilityState === 'visible') ping();
      });
      // Déconnexion explicite à la fermeture du navigateur / de l'onglet.
      // sendBeacon est envoyé de manière garantie même pendant le déchargement.
      // pagehide est plus fiable que beforeunload sur mobile (iOS Safari).
      // On ne déconnecte pas si la page est mise en BFCache (event.persisted).
      function logout(){
        if (navigator.sendBeacon) {
          navigator.sendBeacon('/logout');
        } else {
          fetch('/logout', {method:'GET', keepalive:true, credentials:'omit'});
        }
      }
      window.addEventListener('pagehide', function(e){
        if (!e.persisted) logout();
      });
    "
  }

{ :page, :success_page, :css_content }
