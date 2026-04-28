-- tests/install-openwrt.moon
--
-- Service setup script for OpenWrt CustosVirginum deployment.
-- Handles:
--   - Stopping any running service
--   - Clearing old state
--   - Deploying Lua + nft files
--   - Loading nft rules
--   - Starting workers
--   - Waiting for readiness
--
-- Usage:
--   luajit tests/install-openwrt.lua root@DEST [--no-restart]
--   make install-openwrt HOST=root@DEST

CUSTOS_DIR    = "/usr/share/custos"
CFG_DIR       = "/etc/custos"
SESSIONS_FILE = "#{CUSTOS_DIR}/tmp/sessions.lua"
LOG_MARKER    = "CUSTOS-INSTALL-BEGIN"

C =
  red:    "\27[31m"
  green:  "\27[32m"
  yellow: "\27[33m"
  bold:   "\27[1m"
  reset:  "\27[0m"

SSH_OPTS = "-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes"
SCP_OPTS = "-O #{SSH_OPTS}"

--- Run a local shell command; return (ok, output).
run = (cmd) ->
  fh = io.popen "#{cmd} 2>&1"
  out = fh\read "*a"
  ok  = fh\close!
  ok, out

--- SSH to the router; return (ok, output).
ssh = (cmd) ->
  escaped = cmd\gsub("'", "'\\''")
  run "ssh #{SSH_OPTS} #{SSH_TARGET} '#{escaped}'"

--- SSH to the router; raise on failure.
ssh_check = (cmd) ->
  ok, out = ssh cmd
  error "SSH failed: #{cmd}\n#{out}" unless ok
  out

--- Retourne une commande shell qui lit logread depuis le marqueur de début.
log_since_start = (filter) ->
  "logread | sed -n '/#{LOG_MARKER}/,$p' | #{filter}"

--