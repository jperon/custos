local ffi = require("ffi")
local H = require("auth.html")
local css
css = require("webui.css").css
local page, nav_html
do
  local _obj_0 = require("webui.handlers.dashboard")
  page, nav_html = _obj_0.page, _obj_0.nav_html
end
ffi.cdef([[  typedef int pid_t;
  pid_t getppid(void);
  int kill(pid_t pid, int sig);
]])
local SIGHUP = 1
local handle_reload
handle_reload = function(req, state)
  local parent_pid = tonumber(ffi.C.getppid())
  local ok = parent_pid > 0 and ffi.C.kill(parent_pid, SIGHUP) == 0
  if ok then
    local body = H.section({
      H.p({
        class = "flash success"
      }, "Rechargement lancé (SIGHUP → PID " .. tostring(parent_pid) .. ")."),
      H.p({
        H.a({
          href = "/admin/"
        }, "← Retour")
      })
    })
    return 200, {
      ["Content-Type"] = "text/html; charset=UTF-8"
    }, page("Rechargement", body)
  else
    local body = H.section({
      H.p({
        class = "flash error"
      }, "Échec du rechargement.")
    })
    return 500, {
      ["Content-Type"] = "text/html; charset=UTF-8"
    }, page("Erreur", body)
  end
end
local handle_status
handle_status = function(req, state)
  local uptime_s = os.time() - (state.started_at or os.time())
  local body = H.section({
    H.h2("Processus"),
    H.p("PID : " .. tostring(require('posix') and require('posix').getpid and require('posix').getpid() or 'n/a')),
    H.p("PID superviseur : " .. tostring(tonumber(ffi.C.getppid()))),
    H.p("Uptime worker : " .. tostring(uptime_s) .. "s")
  } .. H.section({
    H.h2("Actions"),
    H.form({
      method = "POST",
      action = "/admin/system/reload"
    }, H.button({
      type = "submit"
    }, "Recharger la configuration")),
    " ",
    H.a({
      href = "/admin/"
    }, "← Tableau de bord")
  }))
  return 200, {
    ["Content-Type"] = "text/html; charset=UTF-8"
  }, page("Statut", body)
end
return {
  handle_reload = handle_reload,
  handle_status = handle_status
}
