local is_array
is_array = function(t)
  if not (type(t) == "table") then
    return false
  end
  local n = #t
  if n == 0 then
    return false
  end
  for i = 1, n do
    if t[i] == nil then
      return false
    end
  end
  return true
end
local RESERVED_KEYWORDS = {
  ["and"] = 1,
  ["break"] = 1,
  ["do"] = 1,
  ["else"] = 1,
  ["elseif"] = 1,
  ["end"] = 1,
  ["false"] = 1,
  ["for"] = 1,
  ["function"] = 1,
  goto = 1,
  ["if"] = 1,
  ["in"] = 1,
  ["local"] = 1,
  ["nil"] = 1,
  ["not"] = 1,
  ["or"] = 1,
  ["repeat"] = 1,
  ["return"] = 1,
  ["then"] = 1,
  ["true"] = 1,
  ["until"] = 1,
  ["while"] = 1,
  class = 1,
  extends = 1,
  import = 1,
  export = 1,
  unless = 1,
  using = 1,
  switch = 1,
  when = 1,
  with = 1,
  continue = 1
}
local serialize_value
serialize_value = function(v, indent)
  local t = type(v)
  if t == "string" then
    return string.format("%q", v)
  elseif t == "number" or t == "boolean" then
    return tostring(v)
  elseif t == "table" then
    local inner = indent .. "  "
    if is_array(v) then
      local parts
      do
        local _accum_0 = { }
        local _len_0 = 1
        for _index_0 = 1, #v do
          local item = v[_index_0]
          _accum_0[_len_0] = serialize_value(item, inner)
          _len_0 = _len_0 + 1
        end
        parts = _accum_0
      end
      return "{ " .. table.concat(parts, ", ") .. " }"
    else
      local keys
      do
        local _accum_0 = { }
        local _len_0 = 1
        for k in pairs(v) do
          _accum_0[_len_0] = k
          _len_0 = _len_0 + 1
        end
        keys = _accum_0
      end
      table.sort(keys, function(a, b)
        return tostring(a) < tostring(b)
      end)
      if #keys == 0 then
        return "{}"
      end
      local lines = { }
      for _index_0 = 1, #keys do
        local k = keys[_index_0]
        local key_str
        if type(k) == "string" and k:match("^[a-zA-Z_][a-zA-Z0-9_]*$") and not RESERVED_KEYWORDS[k] then
          key_str = k
        else
          key_str = "[" .. serialize_value(k, inner) .. "]"
        end
        lines[#lines + 1] = inner .. key_str .. ": " .. serialize_value(v[k], inner)
      end
      return "{\n" .. table.concat(lines, "\n") .. "\n" .. indent .. "}"
    end
  else
    return "nil"
  end
end
local serialize_config
serialize_config = function(cfg)
  return serialize_value(cfg, "") .. "\n"
end
local write_config
write_config = function(cfg, path)
  local tmp = path .. ".webui.new"
  local fh, err = io.open(tmp, "w")
  if not (fh) then
    return nil, "impossible d'ouvrir " .. tostring(tmp) .. " : " .. tostring(err)
  end
  fh:write(serialize_config(cfg))
  fh:close()
  local ok, rename_err = os.rename(tmp, path)
  if not (ok) then
    return nil, "rename() échoué : " .. tostring(tostring(rename_err))
  end
  return true
end
local read_config
read_config = function(path)
  local ok_moon, moon_base = pcall(require, "moonscript.base")
  if ok_moon and moon_base then
    local chunk, err = moon_base.loadfile(path)
    if chunk then
      local ok, result = pcall(chunk)
      if ok and type(result) == "table" then
        return result, nil
      end
    end
  end
  local fn, err = loadfile(path)
  if not (fn) then
    return nil, err
  end
  local ok, result = pcall(fn)
  if not (ok and type(result) == "table") then
    return nil, tostring(result)
  end
  return result, nil
end
return {
  serialize_config = serialize_config,
  write_config = write_config,
  read_config = read_config
}
