local ffi, libc
do
  local _obj_0 = require("ffi_defs")
  ffi, libc = _obj_0.ffi, _obj_0.libc
end
local bit = require("bit")
local STDOUT_FILENO = 1
local ts = ffi.new("timespec_t")
local now
now = function()
  libc.clock_gettime(0, ts)
  return tonumber(ts.tv_sec)
end
local write_log
write_log = function(level, fields)
  local epoch = now()
  local pid = tonumber(ffi.C.getpid())
  local parts = {
    "[" .. tostring(epoch) .. "]",
    "[" .. tostring(pid) .. "]",
    level
  }
  for k, v in pairs(fields) do
    local sv = tostring(v)
    if sv:find(" ") then
      table.insert(parts, tostring(k) .. "=\"" .. tostring(sv) .. "\"")
    else
      table.insert(parts, tostring(k) .. "=" .. tostring(sv))
    end
  end
  local line = table.concat(parts, " ") .. "\n"
  return libc.write(STDOUT_FILENO, line, #line)
end
local log_allow
log_allow = function(fields)
  return write_log("ALLOW", fields)
end
local log_block
log_block = function(fields)
  return write_log("BLOCK", fields)
end
local log_info
log_info = function(fields)
  return write_log("INFO", fields)
end
local log_warn
log_warn = function(fields)
  return write_log("WARN", fields)
end
local log_error
log_error = function(fields)
  return write_log("ERROR", fields)
end
return {
  write_log = write_log,
  log_allow = log_allow,
  log_block = log_block,
  log_info = log_info,
  log_warn = log_warn,
  log_error = log_error,
  now = now
}
