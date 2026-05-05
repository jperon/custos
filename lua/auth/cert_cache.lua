local log_debug, log_warn
do
  local _obj_0 = require("log")
  log_debug, log_warn = _obj_0.log_debug, _obj_0.log_warn
end
local persist_index
persist_index = function(index_path, index_data)
  local fh = io.open(index_path, "w")
  if not (fh) then
    return false
  end
  local lines = {
    "return {"
  }
  for hostname, entry in pairs(index_data) do
    local escaped_hostname = hostname:gsub('"', '\\"')
    table.insert(lines, string.format('  ["%s"] = {expires_at=%d, accessed_at=%d},', escaped_hostname, entry.expires_at, entry.accessed_at))
  end
  table.insert(lines, "}")
  fh:write(table.concat(lines, "\n"))
  fh:close()
  log_debug({
    action = "cert_cache_persist_index",
    path = index_path
  })
  return true
end
local load_persistent_index
load_persistent_index = function(index_path)
  local fh = io.open(index_path, "r")
  if not (fh) then
    return { }
  end
  local content = fh:read("*a")
  fh:close()
  if not (content and #content > 0) then
    return { }
  end
  local status, result = pcall(loadstring, content)
  if not (status) then
    log_warn({
      action = "cert_cache_load_index_failed",
      path = index_path,
      err = result
    })
    return { }
  end
  local loaded_fn = result()
  log_debug({
    action = "cert_cache_loaded_index",
    path = index_path,
    entries = #loaded_fn
  })
  return loaded_fn or { }
end
local create_cache
create_cache = function(max_size, ttl, cert_dir)
  if max_size == nil then
    max_size = 500
  end
  if ttl == nil then
    ttl = 7776000
  end
  if cert_dir == nil then
    cert_dir = "tmp/certs"
  end
  max_size = math.max(1, tonumber(max_size) or 500)
  ttl = math.max(60, tonumber(ttl) or 7776000)
  cert_dir = cert_dir or "tmp/certs"
  local index_path = "tmp/cert_cache_index.lua"
  os.execute("mkdir -p " .. tostring(cert_dir) .. " 2>/dev/null")
  local data = { }
  local lru_order = { }
  local persistent_index = load_persistent_index(index_path)
  local save_cert_to_disk
  save_cert_to_disk = function(hostname, cert_pem, key_pem)
    local hostname_lower = hostname:lower()
    local cert_file = tostring(cert_dir) .. "/" .. tostring(hostname_lower) .. ".crt"
    local key_file = tostring(cert_dir) .. "/" .. tostring(hostname_lower) .. ".key"
    local cert_fh, cert_err = io.open(cert_file, "w")
    if not (cert_fh) then
      log_warn({
        action = "cert_cache_disk_write_failed",
        file = cert_file,
        reason = cert_err or "io.open failed"
      })
      return false
    end
    cert_fh:write(cert_pem)
    cert_fh:close()
    local key_fh, key_err = io.open(key_file, "w")
    if not (key_fh) then
      log_warn({
        action = "cert_cache_disk_write_failed",
        file = key_file,
        reason = key_err or "io.open failed"
      })
      os.remove(cert_file)
      return false
    end
    key_fh:write(key_pem)
    key_fh:close()
    log_debug({
      action = "cert_cache_disk_saved",
      hostname = hostname_lower
    })
    return true
  end
  local load_cert_from_disk
  load_cert_from_disk = function(hostname)
    local hostname_lower = hostname:lower()
    local cert_file = tostring(cert_dir) .. "/" .. tostring(hostname_lower) .. ".crt"
    local key_file = tostring(cert_dir) .. "/" .. tostring(hostname_lower) .. ".key"
    local cert_fh = io.open(cert_file, "r")
    local key_fh = io.open(key_file, "r")
    if not (cert_fh and key_fh) then
      return nil, nil
    end
    local cert_pem = cert_fh:read("*a")
    local key_pem = key_fh:read("*a")
    cert_fh:close()
    key_fh:close()
    if not (cert_pem and key_pem and #cert_pem > 0 and #key_pem > 0) then
      return nil, nil
    end
    log_debug({
      action = "cert_cache_disk_loaded",
      hostname = hostname_lower
    })
    return cert_pem, key_pem
  end
  local set
  set = function(hostname, cert_pem, key_pem, ctx)
    if not (hostname and #hostname > 0) then
      return false
    end
    local hostname_lower = hostname:lower()
    local now = os.time()
    local expires_at = now + ttl
    if not (save_cert_to_disk(hostname_lower, cert_pem, key_pem)) then
      log_warn({
        action = "cert_cache_set_disk_failed",
        hostname = hostname_lower,
        reason = "save_cert_to_disk returned false"
      })
      return false
    end
    persistent_index[hostname_lower] = {
      expires_at = expires_at,
      accessed_at = now
    }
    persist_index(index_path, persistent_index)
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
    local persistent_entry = persistent_index[hostname_lower]
    if persistent_entry then
      local now = os.time()
      if now >= persistent_entry.expires_at then
        log_debug({
          action = "cert_cache_disk_expired",
          hostname = hostname_lower
        })
        persistent_index[hostname_lower] = nil
        persist_index(index_path, persistent_index)
        return nil
      end
    end
    local entry = data[hostname_lower]
    if entry then
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
        hostname = hostname_lower,
        source = "ram"
      })
      return entry
    end
    local cert_pem, key_pem = load_cert_from_disk(hostname_lower)
    if cert_pem and key_pem then
      local now = os.time()
      local expires_at
      if persistent_entry then
        expires_at = persistent_entry.expires_at
      else
        expires_at = (now + ttl)
      end
      entry = {
        cert_pem = cert_pem,
        key_pem = key_pem,
        ctx = nil,
        expires_at = expires_at,
        accessed_at = now
      }
      table.insert(lru_order, hostname_lower)
      while #lru_order > max_size do
        local victim = table.remove(lru_order, 1)
        data[victim] = nil
      end
      data[hostname_lower] = entry
      log_debug({
        action = "cert_cache_hit",
        hostname = hostname_lower,
        source = "disk"
      })
      return entry
    end
    log_debug({
      action = "cert_cache_miss",
      hostname = hostname_lower,
      reason = "not_found"
    })
    return nil
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
    end
    os.remove(tostring(cert_dir) .. "/" .. tostring(hostname_lower) .. ".crt")
    os.remove(tostring(cert_dir) .. "/" .. tostring(hostname_lower) .. ".key")
    persistent_index[hostname_lower] = nil
    persist_index(index_path, persistent_index)
    log_debug({
      action = "cert_cache_delete",
      hostname = hostname_lower
    })
    return true
  end
  local purge_expired
  purge_expired = function()
    local now = os.time()
    local removed_count = 0
    local expired_hosts = { }
    for hostname, entry in pairs(persistent_index) do
      if now >= entry.expires_at then
        table.insert(expired_hosts, hostname)
      end
    end
    for _index_0 = 1, #expired_hosts do
      local hostname = expired_hosts[_index_0]
      os.remove(tostring(cert_dir) .. "/" .. tostring(hostname) .. ".crt")
      os.remove(tostring(cert_dir) .. "/" .. tostring(hostname) .. ".key")
      persistent_index[hostname] = nil
      removed_count = removed_count + 1
    end
    if #expired_hosts > 0 then
      persist_index(index_path, persistent_index)
    end
    local expired_ram = { }
    for hostname, entry in pairs(data) do
      if now >= entry.expires_at then
        table.insert(expired_ram, hostname)
      end
    end
    for _index_0 = 1, #expired_ram do
      local hostname = expired_ram[_index_0]
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
      size_ram = #lru_order,
      size_disk = #persistent_index,
      max_size = max_size,
      ttl_seconds = ttl
    }
  end
  local clear
  clear = function()
    data = { }
    lru_order = { }
    os.execute("rm -f " .. tostring(cert_dir) .. "/*.crt " .. tostring(cert_dir) .. "/*.key 2>/dev/null")
    persistent_index = { }
    persist_index(index_path, persistent_index)
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
