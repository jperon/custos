local CUSTOS_DIR = "/usr/share/custos"
local CFG_DIR = "/etc/custos"
local SESSIONS_FILE = tostring(CUSTOS_DIR) .. "/tmp/sessions.lua"
local LOG_MARKER = "CUSTOS-INSTALL-BEGIN"
local C = {
  red = "\27[31m",
  green = "\27[32m",
  yellow = "\27[33m",
  bold = "\27[1m",
  reset = "\27[0m"
}
local SSH_OPTS = "-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes"
local SCP_OPTS = "-O " .. tostring(SSH_OPTS)
local run
run = function(cmd)
  local fh = io.popen(tostring(cmd) .. " 2>&1")
  local out = fh:read("*a")
  local ok = fh:close()
  return ok, out
end
local ssh
ssh = function(cmd)
  local escaped = cmd:gsub("'", "'\\''")
  return run("ssh " .. tostring(SSH_OPTS) .. " " .. tostring(SSH_TARGET) .. " '" .. tostring(escaped) .. "'")
end
local ssh_check
ssh_check = function(cmd)
  local ok, out = ssh(cmd)
  if not (ok) then
    error("SSH failed: " .. tostring(cmd) .. "\n" .. tostring(out))
  end
  return out
end
local log_since_start
log_since_start = function(filter)
  return "logread | sed -n '/" .. tostring(LOG_MARKER) .. "/,$p' | " .. tostring(filter)
end
