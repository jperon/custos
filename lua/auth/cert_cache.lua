local log_debug, log_warn
do
  local _obj_0 = require("log")
  log_debug, log_warn = _obj_0.log_debug, _obj_0.log_warn
end
local create_cache
create_cache = function(max_size, ttl)
  if max_size == nil then
    max_size = 100
  end
  if ttl == nil then
    ttl = 86400
  end
  max_size = math.max(1, tonumber(max_size) or 100)
  ttl = math.max(60, tonumber(ttl) or 86400)
  local data = { }
  local lru_order = { }
  local set
  set = function(hostname, cert_pem, key_pem, ctx)
    if not (hostname and #hostname > 0) then
      return false
    end
    local hostname_lower = hostname:lower()
    local now = os.time()
    local expires_at = now + ttl
    if data[hostname_lower] then
      for i = 1, #lru_order do
        if lru_order[i] == hostname_lower then
          table.remove(lru_order, i)
          break
        end
      end
    end
    table.insert(lru_order, hostname_lower)
    while #lru_order > max_size do
      local victim = table.remove(lru_order, 1)
      data[victim] = nil
      log_debug({
        action = "cert_cache_evict",
        hostname = victim,
        reason = "lru_full"
      })
    end
    data[hostname_lower] = {
      cert_pem = cert_pem,
      key_pem = key_pem,
      ctx = ctx,
      expires_at = expires_at,
      accessed_at = now
    }
    log_debug({
      action = "cert_cache_set",
      hostname = hostname_lower,
      size = #lru_order
    })
    return true
  end
  local get
  get = function(hostname)
    if not (hostname and #hostname > 0) then
      return nil
    end
    local hostname_lower = hostname:lower()
    local entry = data[hostname_lower]
    if not (entry) then
      log_debug({
        action = "cert_cache_miss",
        hostname = hostname_lower,
        reason = "not_found"
      })
      return nil
    end
    local now = os.time()
    if now >= entry.expires_at then
      data[hostname_lower] = nil
      for i = 1, #lru_order do
        if lru_order[i] == hostname_lower then
          table.remove(lru_order, i)
          break
        end
      end
      log_debug({
        action = "cert_cache_expired",
        hostname = hostname_lower
      })
      return nil
    end
    for i = 1, #lru_order do
      if lru_order[i] == hostname_lower then
        table.remove(lru_order, i)
        break
      end
    end
    table.insert(lru_order, hostname_lower)
    entry.accessed_at = now
    log_debug({
      action = "cert_cache_hit",
      hostname = hostname_lower
    })
    return entry
  end
  local delete
  delete = function(hostname)
    if not (hostname and #hostname > 0) then
      return false
    end
    local hostname_lower = hostname:lower()
    if data[hostname_lower] then
      data[hostname_lower] = nil
      for i = 1, #lru_order do
        if lru_order[i] == hostname_lower then
          table.remove(lru_order, i)
          break
        end
      end
      log_debug({
        action = "cert_cache_delete",
        hostname = hostname_lower
      })
      return true
    end
    return false
  end
  local purge_expired
  purge_expired = function()
    local now = os.time()
    local removed_count = 0
    local expired_hosts = { }
    for hostname, entry in pairs(data) do
      if now >= entry.expires_at then
        table.insert(expired_hosts, hostname)
      end
    end
    for _index_0 = 1, #expired_hosts do
      local hostname = expired_hosts[_index_0]
      data[hostname] = nil
      for i = 1, #lru_order do
        if lru_order[i] == hostname then
          table.remove(lru_order, i)
          break
        end
      end
      removed_count = removed_count + 1
    end
    if removed_count > 0 then
      log_debug({
        action = "cert_cache_purge_expired",
        count = removed_count
      })
    end
    return removed_count
  end
  local stats
  stats = function()
    return {
      size = #lru_order,
      max_size = max_size,
      ttl_seconds = ttl
    }
  end
  local clear
  clear = function()
    data = { }
    lru_order = { }
    log_debug({
      action = "cert_cache_clear"
    })
    return true
  end
  return {
    set = set,
    get = get,
    delete = delete,
    purge_expired = purge_expired,
    stats = stats,
    clear = clear
  }
end
return {
  create_cache = create_cache
}
