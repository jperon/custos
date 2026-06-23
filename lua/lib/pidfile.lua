local DEFAULT_PATH = "/var/run/custos.pid"
local resolve_path
resolve_path = function(cfg_path)
  return cfg_path or os.getenv("CUSTOS_PID_FILE") or DEFAULT_PATH
end
local write
write = function(pid, path)
  path = path or resolve_path()
  local ok = pcall(function()
    local fh = assert(io.open(path, "w"))
    fh:write(tostring(pid))
    return fh:close()
  end)
  return ok
end
local remove
remove = function(path)
  path = path or resolve_path()
  pcall(function()
    return os.remove(path)
  end)
  return nil
end
local read
read = function(path)
  path = path or resolve_path()
  local fh = io.open(path, "r")
  if not (fh) then
    return nil, "pidfile introuvable : " .. tostring(path)
  end
  local content = fh:read("*a")
  fh:close()
  local pid = tonumber((content or ""):match("%d+"))
  if not (pid and pid > 0) then
    return nil, "pidfile illisible : " .. tostring(path)
  end
  return pid
end
return {
  resolve_path = resolve_path,
  write = write,
  remove = remove,
  read = read,
  DEFAULT_PATH = DEFAULT_PATH
}
