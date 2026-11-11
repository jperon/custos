-- src/webui/handlers/system.moon
-- POST /admin/system/reload  — envoie SIGHUP au SUPERVISEUR (via pidfile)
-- GET  /admin/system/status  — affiche les infos système
--
-- Le hot-reload de la config n'est traité que par le superviseur (main.moon) ;
-- le worker AUTH, lui, ne relit que les secrets sur SIGHUP. La webui s'exécutant
-- dans un enfant AUTH-conn (petit-enfant du superviseur), getppid() viserait le
-- worker AUTH — d'où l'usage du pidfile (src/lib/pidfile.moon) pour cibler le
-- superviseur.

ffi = require "ffi"
H   = require "auth.html"
pidfile = require "lib.pidfile"
{ :page } = require "webui.handlers.dashboard"
audit = require "webui.audit"

pcall ->
  ffi.cdef [[
    typedef int pid_t;
    pid_t getpid(void);
    pid_t getppid(void);
    int kill(pid_t pid, int sig);
  ]]

SIGHUP = 1

-- kill injectable pour les tests (évite d'envoyer un vrai SIGHUP).
default_kill = (pid, sig) -> ffi.C.kill(pid, sig) == 0

handle_reload = (req, state) ->
  pid_path = pidfile.resolve_path state and state.pid_file
  kill_fn  = (state and state.kill_fn) or default_kill
  pid, err = pidfile.read pid_path
  ok = pid and kill_fn(pid, SIGHUP)
  if pid and ok
    audit.change req, "webui_reload_requested", { pid: pid }
  elseif pid
    audit.fail req, "webui_reload_requested", { pid: pid }, "kill_failed"
  else
    audit.fail req, "webui_reload_requested", {}, "pidfile_unreadable"
  body = if ok
    H.section {
      H.p { class: "flash success" }, "Rechargement lancé (SIGHUP → superviseur PID #{pid})."
      H.p { H.a { href: "/admin/" }, "← Retour" }
    }
  else
    H.section {
      H.p { class: "flash error" }, "Échec du rechargement : #{err or "superviseur injoignable (PID #{pid})"}."
    }
  status = if ok then 200 else 500
  status, { ["Content-Type"]: "text/html; charset=UTF-8" }, page "Rechargement", body

handle_status = (req, state) ->
  uptime_s = os.time! - (state.started_at or os.time!)
  s1 = H.section {
    H.h2 "Processus"
    H.p "PID : #{tonumber ffi.C.getpid!}"
    H.p "PID superviseur : #{tonumber ffi.C.getppid!}"
    H.p "Uptime worker : #{uptime_s}s"
  }
  s2 = H.section {
    H.h2 "Actions"
    H.form { method: "POST", action: "/admin/system/reload" }, {
      H.button { type: "submit" }, "Recharger la configuration"
    }
    " "
    H.a { href: "/admin/" }, "← Tableau de bord"
  }
  200, { ["Content-Type"]: "text/html; charset=UTF-8" }, page "Statut", s1 .. s2

{ :handle_reload, :handle_status }
