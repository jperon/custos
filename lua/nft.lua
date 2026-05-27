local ffi, libnft
do
  local _obj_0 = require("ffi_defs")
  ffi, libnft = _obj_0.ffi, _obj_0.libnft
end
local config = require("config")
local log_warn, log_error
do
  local _obj_0 = require("log")
  log_warn, log_error = _obj_0.log_warn, _obj_0.log_error
end
local ctx = libnft.nft_ctx_new(0)
if ctx == nil then
  error("nft_ctx_new() échoué")
end
local ok_buf = pcall(function()
  return libnft.nft_ctx_buffer_error(ctx)
end)
local get_error_buffer
get_error_buffer = function()
  if not (ok_buf) then
    return nil
  end
  local ok, ptr = pcall(function()
    return libnft.nft_ctx_get_error_buffer(ctx)
  end)
  if not (ok and ptr ~= nil) then
    return nil
  end
  local msg = ffi.string(ptr)
  if msg and msg ~= "" then
    return msg
  end
end
local run_cmd
run_cmd = function(cmd, opts)
  if opts == nil then
    opts = nil
  end
  local rc = libnft.nft_run_cmd_from_buffer(ctx, cmd)
  if rc ~= 0 then
    local ts = os.time()
    local nft_err = get_error_buffer()
    local busy = nft_err and nft_err:match("Resource busy")
    if not (opts and opts.quiet) then
      log_warn(function()
        return {
          action = "nft_cmd_failed",
          cmd = cmd,
          rc = rc,
          ts = ts,
          nft_err = nft_err or "",
          transient = busy and "resource_busy" or ""
        }
      end)
    end
    return false, nft_err
  end
  return true, nil
end
local add_ip4
add_ip4 = function(client_ip, ip_str)
  local cmd = "add element " .. tostring(config.nft.family) .. " " .. tostring(config.nft.table) .. " " .. tostring(config.nft.set_ip4) .. " { " .. tostring(client_ip) .. " . " .. tostring(ip_str) .. " timeout " .. tostring(config.nft.ip_timeout) .. " }"
  return run_cmd(cmd)
end
local add_ip4_quiet
add_ip4_quiet = function(client_ip, ip_str)
  local cmd = "add element " .. tostring(config.nft.family) .. " " .. tostring(config.nft.table) .. " " .. tostring(config.nft.set_ip4) .. " { " .. tostring(client_ip) .. " . " .. tostring(ip_str) .. " timeout " .. tostring(config.nft.ip_timeout) .. " }"
  local ok, err = run_cmd(cmd, {
    quiet = true
  })
  return ok, err or "nft add ip4 failed"
end
local add_ip6
add_ip6 = function(client_ip, ip_str)
  if not (client_ip:find(":")) then
    return false
  end
  local cmd = "add element " .. tostring(config.nft.family6) .. " " .. tostring(config.nft.table) .. " " .. tostring(config.nft.set_ip6) .. " { " .. tostring(client_ip) .. " . " .. tostring(ip_str) .. " timeout " .. tostring(config.nft.ip_timeout) .. " }"
  return run_cmd(cmd)
end
local add_ip6_quiet
add_ip6_quiet = function(client_ip, ip_str)
  if not (client_ip:find(":")) then
    return false
  end
  local cmd = "add element " .. tostring(config.nft.family6) .. " " .. tostring(config.nft.table) .. " " .. tostring(config.nft.set_ip6) .. " { " .. tostring(client_ip) .. " . " .. tostring(ip_str) .. " timeout " .. tostring(config.nft.ip_timeout) .. " }"
  local ok, err = run_cmd(cmd, {
    quiet = true
  })
  return ok, err or "nft add ip6 failed"
end
local add_ip
add_ip = function(client_ip, ip_str)
  if ip_str:find(":") then
    return add_ip6(client_ip, ip_str)
  else
    return add_ip4(client_ip, ip_str)
  end
end
local add_mac4
add_mac4 = function(mac, ip_str)
  if not (config.nft.set_mac4) then
    return false
  end
  local cmd = "add element " .. tostring(config.nft.family) .. " " .. tostring(config.nft.table) .. " " .. tostring(config.nft.set_mac4) .. " { " .. tostring(mac) .. " . " .. tostring(ip_str) .. " timeout " .. tostring(config.nft.ip_timeout) .. " }"
  return run_cmd(cmd)
end
local add_mac4_quiet
add_mac4_quiet = function(mac, ip_str)
  if not (config.nft.set_mac4) then
    return false
  end
  local cmd = "add element " .. tostring(config.nft.family) .. " " .. tostring(config.nft.table) .. " " .. tostring(config.nft.set_mac4) .. " { " .. tostring(mac) .. " . " .. tostring(ip_str) .. " timeout " .. tostring(config.nft.ip_timeout) .. " }"
  local ok, err = run_cmd(cmd, {
    quiet = true
  })
  return ok, err or "nft add mac4 failed"
end
local add_mac6
add_mac6 = function(mac, ip_str)
  if not (config.nft.set_mac6) then
    return false
  end
  local cmd = "add element " .. tostring(config.nft.family6) .. " " .. tostring(config.nft.table) .. " " .. tostring(config.nft.set_mac6) .. " { " .. tostring(mac) .. " . " .. tostring(ip_str) .. " timeout " .. tostring(config.nft.ip_timeout) .. " }"
  return run_cmd(cmd)
end
local add_mac6_quiet
add_mac6_quiet = function(mac, ip_str)
  if not (config.nft.set_mac6) then
    return false
  end
  local cmd = "add element " .. tostring(config.nft.family6) .. " " .. tostring(config.nft.table) .. " " .. tostring(config.nft.set_mac6) .. " { " .. tostring(mac) .. " . " .. tostring(ip_str) .. " timeout " .. tostring(config.nft.ip_timeout) .. " }"
  local ok, err = run_cmd(cmd, {
    quiet = true
  })
  return ok, err or "nft add mac6 failed"
end
local cleanup
cleanup = function()
  if ctx ~= nil then
    return libnft.nft_ctx_free(ctx)
  end
end
return {
  add_ip4 = add_ip4,
  add_ip6 = add_ip6,
  add_ip = add_ip,
  add_mac4 = add_mac4,
  add_mac6 = add_mac6,
  add_ip4_quiet = add_ip4_quiet,
  add_ip6_quiet = add_ip6_quiet,
  add_mac4_quiet = add_mac4_quiet,
  add_mac6_quiet = add_mac6_quiet,
  run_cmd = run_cmd,
  cleanup = cleanup
}
