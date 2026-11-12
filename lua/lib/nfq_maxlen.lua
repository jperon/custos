local ffi = require("ffi")
local log_info, log_warn, log_debug
do
  local _obj_0 = require("log")
  log_info, log_warn, log_debug = _obj_0.log_info, _obj_0.log_warn, _obj_0.log_debug
end
local DEFAULT_MAXLEN = 4096
local LOWMEM_MAXLEN = 1024
local resolve_maxlen
resolve_maxlen = function(configured, is_lowmem)
  local v = tonumber(configured)
  if v and v > 0 and v % 1 == 0 then
    return v
  end
  if is_lowmem then
    return LOWMEM_MAXLEN
  else
    return DEFAULT_MAXLEN
  end
end
local api_available
api_available = function(libnfq)
  if not (libnfq) then
    return false
  end
  local ok, fn = pcall(function()
    return libnfq.nfq_set_queue_maxlen
  end)
  return ok and fn and true or false
end
local apply_maxlen
apply_maxlen = function(libnfq, qh, maxlen)
  if not (api_available(libnfq)) then
    return nil
  end
  local rc = libnfq.nfq_set_queue_maxlen(qh, maxlen)
  return {
    maxlen = maxlen,
    rc = rc,
    ok = rc >= 0
  }
end
local configure
configure = function(libnfq, libc, qh, queue_num, configured, is_lowmem)
  local maxlen = resolve_maxlen(configured, is_lowmem)
  local res = apply_maxlen(libnfq, qh, maxlen)
  if not (res) then
    log_debug(function()
      return {
        action = "queue_maxlen_unavailable",
        queue = queue_num
      }
    end)
    return nil
  end
  if res.ok then
    log_info(function()
      return {
        action = "queue_maxlen",
        queue = queue_num,
        maxlen = maxlen
      }
    end)
  else
    local errno = nil
    if libc and libc.__errno_location then
      local ok, val = pcall(function()
        return tonumber(libc.__errno_location()[0])
      end)
      if ok then
        errno = val
      end
    end
    log_warn(function()
      return {
        action = "queue_maxlen_failed",
        queue = queue_num,
        maxlen = maxlen,
        rc = res.rc,
        errno = errno
      }
    end)
  end
  return res
end
return {
  DEFAULT_MAXLEN = DEFAULT_MAXLEN,
  LOWMEM_MAXLEN = LOWMEM_MAXLEN,
  resolve_maxlen = resolve_maxlen,
  api_available = api_available,
  apply_maxlen = apply_maxlen,
  configure = configure
}
