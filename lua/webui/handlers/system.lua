local ffi = require("ffi")
local H = require("auth.html")
local page
page = require("webui.handlers.dashboard").page
pcall(function()
  return ffi.cdef([[    typedef int pid_t;
    pid_t getpid(void);
    pid_t getppid(void);
    int kill(pid_t pid, int sig);
  ]])
end)
local SIGHUP = 1
local handle_reload
handle_reload = function(req, state)
  local parent_pid = tonumber(ffi.C.getppid())
  local ok = parent_pid > 0 and ffi.C.kill(parent_pid, SIGHUP) == 0
  local body
  if ok then
    body = H.section({
      H.p({
        class = "flash success"
      }, "Rechargement lancé (SIGHUP → PID " .. tostring(parent_pid) .. ")."),
      H.p({
        H.a({
          href = "/admin/"
        }, "← Retour")
      })
    })
  else
    body = H.section({
      H.p({
        class = "flash error"
      }, "Échec du rechargement.")
    })
  end
  local status
  if ok then
    status = 200
  else
    status = 500
  end
  return status, {
    ["Content-Type"] = "text/html; charset=UTF-8"
  }, page("Rechargement", body)
end
local handle_status
handle_status = function(req, state)
  local uptime_s = os.time() - (state.started_at or os.time())
  local s1 = H.section({
    H.h2("Processus"),
    H.p("PID : " .. tostring(tonumber(ffi.C.getpid()))),
    H.p("PID superviseur : " .. tostring(tonumber(ffi.C.getppid()))),
    H.p("Uptime worker : " .. tostring(uptime_s) .. "s")
  })
  local s2 = H.section({
    H.h2("Actions"),
    H.form({
      method = "POST",
      action = "/admin/system/reload"
    }, {
      H.button({
        type = "submit"
      }, "Recharger la configuration")
    }),
    " ",
    H.a({
      href = "/admin/"
    }, "← Tableau de bord")
  })
  return 200, {
    ["Content-Type"] = "text/html; charset=UTF-8"
  }, page("Statut", s1 .. s2)
end
return {
  handle_reload = handle_reload,
  handle_status = handle_status
}
