local H = require("auth.html")
local css_content = [[  * {
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
local page
page = function(self)
  return "<!DOCTYPE html>\n" .. H.html({
    lang = "fr",
    H.head({
      H.meta({
        charset = "UTF-8"
      }),
      H.title("CustosVirginum"),
      H.link({
        rel = "icon",
        href = "data:image/svg+xml,<svg viewBox='0 0 100 100'><text y='75' font-size='75'>✞</text></svg>"
      }),
      H.style(css_content)
    }),
    H.body(self)
  })
end
local success_page
success_page = function(auth_cfg, created_at, is_admin)
  local interval = tonumber(auth_cfg and auth_cfg.heartbeat_interval) or 30
  if interval <= 0 then
    interval = 30
  end
  local idle_timeout = tonumber(auth_cfg and auth_cfg.idle_timeout) or 300
  local session_start = tonumber(created_at) or 0
  local admin_link
  if is_admin then
    admin_link = H.p(H.a({
      href = "/admin",
      target = "_blank",
      rel = "noopener"
    }, "Administration"))
  else
    admin_link = ""
  end
  return page({
    H.p("Connexion réussie. Votre accès est actif tant que cette fenêtre est ouverte."),
    H.p({
      id = "session-timer"
    }, "Session ouverte depuis : --"),
    admin_link,
    H.p(H.a({
      href = "/logout"
    }, "Déconnexion")),
    H.script("\n      var iv = " .. tostring(interval) .. " * 1000;\n      var idle = " .. tostring(idle_timeout) .. " * 1000;\n      var sessionStart = " .. tostring(session_start) .. ";\n      var workerJs = \"self.onmessage = function(e) { \\n        if (e.data.type === 'start') { \\n          setInterval(function() { self.postMessage({type: 'tick'}); }, e.data.interval); \\n          setTimeout(function() { self.postMessage({type: 'tick'}); }, 3000); \\n        } \\n        if (e.data.type === 'visible') { self.postMessage({type: 'tick'}); } \\n      }\";\n      var worker = new Worker(URL.createObjectURL(new Blob([workerJs], {type: 'application/javascript'})));\n      var lastSuccess = Date.now();\n      function ping(){\n        fetch('/ping',{method:'GET',credentials:'same-origin'})\n          .then(function(r){\n            lastSuccess = Date.now();\n            if(r.status===401){\n              if(document.visibilityState!=='visible')\n                alert('Connexion perdue, veuillez vous authentifier de nouveau.');\n              location.href='/';\n            }\n          })\n          .catch(function(){\n            if (Date.now() - lastSuccess > idle) {\n              if (document.visibilityState === 'visible') location.href='/';\n            }\n          });\n      }\n      worker.onmessage = function(e) {\n        if (e.data.type === 'tick') ping();\n      };\n      worker.postMessage({type: 'start', interval: iv});\n      function updateTimer(){\n        var now = Math.floor(Date.now() / 1000);\n        var elapsed = now - sessionStart;\n        if (elapsed < 0) elapsed = 0;\n        var h = Math.floor(elapsed / 3600);\n        var m = Math.floor((elapsed % 3600) / 60);\n        var txt;\n        if (h > 0) {\n          txt = h + 'h ' + (m < 10 ? '0' : '') + m + 'min';\n        } else {\n          txt = m + ' min';\n        }\n        var el = document.getElementById('session-timer');\n        if (el) el.textContent = 'Session ouverte depuis : ' + txt;\n      }\n      setInterval(updateTimer, 10000);\n      updateTimer();\n      document.addEventListener('visibilitychange', function(){\n        if (document.visibilityState === 'visible') worker.postMessage({type: 'visible'});\n      });\n      function logout(){\n        if (navigator.sendBeacon) {\n          navigator.sendBeacon('/logout');\n        } else {\n          fetch('/logout', {method:'GET', keepalive:true, credentials:'omit'});\n        }\n      }\n      window.addEventListener('pagehide', function(e){\n        if (!e.persisted) logout();\n      });\n    ")
  })
end
return {
  page = page,
  success_page = success_page,
  css_content = css_content
}
