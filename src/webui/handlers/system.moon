-- src/webui/handlers/system.moon
-- POST /admin/system/reload  — envoie SIGHUP au superviseur
-- GET  /admin/system/status  — affiche les infos système

ffi = require "ffi"
H   = require "auth.html"
{ :css } = require "webui.css"
{ :page, :nav_html } = require "webui.handlers.dashboard"

ffi.cdef [[
  typedef int pid_t;
  pid_t getppid(void);
  int kill(pid_t pid, int sig);
]]

SIGHUP = 1

handle_reload = (req, state) ->
  parent_pid = tonumber ffi.C.getppid!
  ok = parent_pid > 0 and ffi.C.kill(parent_pid, SIGHUP) == 0
  if ok
    body = H.section {
      H.p { class: "flash success" }, "Rechargement lancé (SIGHUP → PID #{parent_pid})."
      H.p { H.a { href: "/admin/" }, "← Retour" }
    }
    200, { ["Content-Type"]: "text/html; charset=UTF-8" }, page "Rechargement", body
  else
    body = H.section { H.p { class: "flash error" }, "Échec du rechargement." }
    500, { ["Content-Type"]: "text/html; charset=UTF-8" }, page "Erreur", body

handle_status = (req, state) ->
  uptime_s = os.time! - (state.started_at or os.time!)
  body = H.section {
    H.h2 "Processus"
    H.p "PID : #{require('posix') and require('posix').getpid and require('posix').getpid() or 'n/a'}"
    H.p "PID superviseur : #{tonumber ffi.C.getppid!}"
    H.p "Uptime worker : #{uptime_s}s"
  } .. H.section {
    H.h2 "Actions"
    H.form { method: "POST", action: "/admin/system/reload" },
      H.button { type: "submit" }, "Recharger la configuration"
    " "
    H.a { href: "/admin/" }, "← Tableau de bord"
  }
  200, { ["Content-Type"]: "text/html; charset=UTF-8" }, page "Statut", body

{ :handle_reload, :handle_status }
