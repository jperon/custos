local serializer = require("webui.serializer")
local is_array
is_array = function(t)
  if not (type(t) == "table") then
    return false
  end
  local n = #t
  if n == 0 then
    return (next(t) == nil)
  end
  for i = 1, n do
    if t[i] == nil then
      return false
    end
  end
  return true
end
local clone
clone = function(v)
  if not (type(v) == "table") then
    return v
  end
  local out = { }
  for k, item in pairs(v) do
    out[k] = clone(item)
  end
  return out
end
local merge_into
merge_into = function(dst, src)
  if not (type(src) == "table") then
    return dst
  end
  for k, v in pairs(src) do
    if type(v) == "table" and type(dst[k]) == "table" and not is_array(v) then
      merge_into(dst[k], v)
    else
      dst[k] = clone(v)
    end
  end
  return dst
end
local parse_args
parse_args = function(args)
  local result = {
    base = nil,
    device = nil,
    output = "/etc/custos/config.moon",
    hostname = nil,
    reload = false
  }
  local i = 1
  while i <= #args do
    local a = args[i]
    if a == "--base" then
      result.base = args[i + 1]
      i = i + 2
    elseif a == "--device" then
      result.device = args[i + 1]
      i = i + 2
    elseif a == "--output" then
      result.output = args[i + 1]
      i = i + 2
    elseif a == "--hostname" then
      result.hostname = args[i + 1]
      i = i + 2
    elseif a == "--reload" then
      result.reload = true
      i = i + 1
    else
      i = i + 1
    end
  end
  return result
end
local opts = parse_args(arg)
if not (opts.base) then
  io.stderr:write("apply: --base <chemin> requis\n")
  os.exit(1)
end
local hostname = opts.hostname
if not (hostname) then
  local fh = io.popen("uname -n")
  hostname = fh:read("*l")
  fh:close()
end
local base_cfg, err = serializer.read_config(opts.base)
if not (base_cfg) then
  io.stderr:write("apply: config de base introuvable " .. tostring(opts.base) .. ": " .. tostring(tostring(err)) .. "\n")
  os.exit(1)
end
local device_path = opts.device
if not (device_path) then
  local base_dir = opts.base:match("^(.+)/base/config%.moon$")
  if base_dir then
    device_path = tostring(base_dir) .. "/devices/" .. tostring(hostname) .. "/config.moon"
  end
end
local device_cfg = nil
if device_path then
  local dev_err
  device_cfg, dev_err = serializer.read_config(device_path)
  if not device_cfg and dev_err and not tostring(dev_err):match("No such file") then
    io.stderr:write("apply: avertissement " .. tostring(device_path) .. ": " .. tostring(tostring(dev_err)) .. "\n")
  end
end
local merged = clone(base_cfg)
if device_cfg then
  merge_into(merged, device_cfg)
end
local ok, write_err = serializer.write_config(merged, opts.output)
if not (ok) then
  io.stderr:write("apply: écriture échouée " .. tostring(opts.output) .. ": " .. tostring(tostring(write_err)) .. "\n")
  os.exit(1)
end
if opts.reload then
  local ret = os.execute("pkill -SIGHUP -f 'luajit.*main' 2>/dev/null")
  if ret ~= 0 then
    io.stderr:write("apply: SIGHUP non envoyé (service inactif ?)\n")
  end
end
return io.stdout:write("apply: " .. tostring(opts.output) .. " mis à jour\n")
