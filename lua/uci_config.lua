local script_dir = (arg and arg[0] or ""):match("^(.*)/") or "."
package.path = tostring(script_dir) .. "/?.lua;" .. tostring(package.path)
local C = require("config")
local UCI_PKG = "custos"
local UCI_SEC = "main"
local OUTPUT_DIR = "/var/run/custos"
local uci_get
uci_get = function(option)
  local fh = io.popen("uci get " .. tostring(UCI_PKG) .. "." .. tostring(UCI_SEC) .. "." .. tostring(option) .. " 2>/dev/null")
  if not (fh) then
    return nil
  end
  local val = fh:read("*l")
  fh:close()
  if val and val ~= "" then
    return val
  end
end
local uci_get_list
uci_get_list = function(option)
  local fh = io.popen("uci show " .. tostring(UCI_PKG) .. "." .. tostring(UCI_SEC) .. "." .. tostring(option) .. " 2>/dev/null")
  if not (fh) then
    return nil
  end
  local content = fh:read("*a")
  fh:close()
  if not content or content:match("^%s*$") then
    return nil
  end
  local result = { }
  for val in content:gmatch("'([^']*)'") do
    table.insert(result, val)
  end
  return result
end
local coerce
coerce = function(raw, default)
  local _exp_0 = type(default)
  if "number" == _exp_0 then
    return tonumber(raw) or default
  elseif "boolean" == _exp_0 then
    if raw == "1" or raw == "true" then
      return true
    end
    if raw == "0" or raw == "false" then
      return false
    end
    return default
  else
    return raw
  end
end
local resolve
resolve = function()
  local cfg = { }
  for k, v in pairs(C) do
    local option = k:lower()
    if type(v) == "table" then
      cfg[k] = uci_get_list(option) or v
    else
      local raw = uci_get(option)
      if raw then
        cfg[k] = coerce(raw, v)
      else
        cfg[k] = v
      end
    end
  end
  return cfg
end
local serialize
serialize = function(v)
  local _exp_0 = type(v)
  if "number" == _exp_0 then
    return tostring(v)
  elseif "boolean" == _exp_0 then
    return tostring(v)
  elseif "string" == _exp_0 then
    return string.format('"%s"', v:gsub("\\", "\\\\"):gsub('"', '\\"'))
  elseif "table" == _exp_0 then
    local items
    do
      local _accum_0 = { }
      local _len_0 = 1
      for _index_0 = 1, #v do
        local item = v[_index_0]
        _accum_0[_len_0] = serialize(item)
        _len_0 = _len_0 + 1
      end
      items = _accum_0
    end
    return #items == 0 and "{}" or "{ " .. tostring(table.concat(items, ', ')) .. " }"
  else
    return error("serialize: type non supporté : " .. tostring(type(v)) .. " (" .. tostring(tostring(v)) .. ")")
  end
end
local generate_config
generate_config = function(cfg)
  local lines = {
    "-- config.lua — généré par uci_config.lua depuis /etc/config/custos",
    "-- Ne pas modifier : écrasé au démarrage/rechargement du service.",
    ""
  }
  local keys
  do
    local _accum_0 = { }
    local _len_0 = 1
    for k, _ in pairs(cfg) do
      _accum_0[_len_0] = k
      _len_0 = _len_0 + 1
    end
    keys = _accum_0
  end
  table.sort(keys)
  for _index_0 = 1, #keys do
    local k = keys[_index_0]
    table.insert(lines, string.format("local %-32s = %s", k, serialize(cfg[k])))
  end
  table.insert(lines, "")
  table.insert(lines, "return {")
  for _index_0 = 1, #keys do
    local k = keys[_index_0]
    table.insert(lines, string.format("  %-32s = %s,", k, k))
  end
  table.insert(lines, "}")
  return table.concat(lines, "\n")
end
local main
main = function()
  local cfg = resolve()
  if os.execute("mkdir -p " .. tostring(OUTPUT_DIR)) ~= 0 then
    io.stderr:write("uci_config: impossible de créer " .. tostring(OUTPUT_DIR) .. "\n")
    os.exit(1)
  end
  local tmp_path = tostring(OUTPUT_DIR) .. "/config.lua.tmp"
  local output_path = tostring(OUTPUT_DIR) .. "/config.lua"
  local fh, err = io.open(tmp_path, "w")
  if not (fh) then
    io.stderr:write("uci_config: écriture impossible " .. tostring(tmp_path) .. ": " .. tostring(err) .. "\n")
    os.exit(1)
  end
  fh:write(generate_config(cfg))
  fh:close()
  local ok, mv_err = os.rename(tmp_path, output_path)
  if not (ok) then
    io.stderr:write("uci_config: rename échoué: " .. tostring(mv_err) .. "\n")
    os.execute("rm -f " .. tostring(tmp_path))
    os.exit(1)
  end
  return io.write("uci_config: " .. tostring(output_path) .. " écrit\n")
end
return main()
