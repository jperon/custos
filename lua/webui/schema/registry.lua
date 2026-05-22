local compiler_api = require("filter.compiler_api")
local find_lua_dir
find_lua_dir = function()
  local path = package.searchpath("filter.conditions.from_net", package.path)
  if path then
    local dir = path:match("^(.+)/filter/conditions/from_net%.lua$")
    if dir then
      return dir
    end
  end
  return "lua"
end
local list_lua_files
list_lua_files = function(dir)
  local names = { }
  local fh = io.popen("ls -1 '" .. tostring(dir) .. "' 2>/dev/null")
  if not (fh) then
    return names
  end
  for line in fh:lines() do
    local name = line:match("^(.+)%.lua$")
    if name and name ~= "init" then
      names[#names + 1] = name
    end
  end
  fh:close()
  return names
end
local variant_labels
variant_labels = function(base_schema, variant)
  if not (base_schema) then
    return nil
  end
  local s
  do
    local _tbl_0 = { }
    for k, v in pairs(base_schema) do
      _tbl_0[k] = v
    end
    s = _tbl_0
  end
  if variant == "plural" then
    s.label = (s.label or "") .. " (plusieurs)"
    s.arg_type = "string_list"
    s.arg_hint = nil
  elseif variant == "list" then
    s.label = (s.label or "") .. " (liste nommée)"
    s.arg_type = "string"
    s.arg_hint = "nom d'un fichier dans lists_dir"
  elseif variant == "lists" then
    s.label = (s.label or "") .. " (plusieurs listes nommées)"
    s.arg_type = "string_list"
    s.arg_hint = nil
  end
  return s
end
local base_of_variant
base_of_variant = function(name)
  local b = name:match("^(.+)_lists$")
  if b then
    return b
  end
  b = name:match("^(.+)_list$")
  if b then
    return b
  end
  b = name:match("^(.+)s$")
  if b then
    return b
  end
  return nil
end
local variant_type
variant_type = function(name)
  if name:match("_lists$") then
    return "lists"
  end
  if name:match("_list$") then
    return "list"
  end
  return "plural"
end
local build_condition_registry
build_condition_registry = function()
  local lua_dir = find_lua_dir()
  local cond_dir = lua_dir .. "/filter/conditions"
  local registry = { }
  local names = list_lua_files(cond_dir)
  for _index_0 = 1, #names do
    local name = names[_index_0]
    local s = compiler_api.get_condition_schema(name)
    if s then
      registry[name] = s
    end
  end
  local base_names
  do
    local _accum_0 = { }
    local _len_0 = 1
    for name in pairs(registry) do
      _accum_0[_len_0] = name
      _len_0 = _len_0 + 1
    end
    base_names = _accum_0
  end
  for _index_0 = 1, #base_names do
    local base_name = base_names[_index_0]
    local base_schema = registry[base_name]
    local plural = base_name .. "s"
    if not (registry[plural]) then
      local s = variant_labels(base_schema, "plural")
      if s then
        registry[plural] = s
      end
    end
    local list = base_name .. "_list"
    if not (registry[list]) then
      local s = variant_labels(base_schema, "list")
      if s then
        registry[list] = s
      end
    end
    local lists = base_name .. "_lists"
    if not (registry[lists]) then
      local s = variant_labels(base_schema, "lists")
      if s then
        registry[lists] = s
      end
    end
  end
  return registry
end
local build_action_registry
build_action_registry = function()
  local lua_dir = find_lua_dir()
  local action_dir = lua_dir .. "/filter/actions"
  local registry = { }
  local names = list_lua_files(action_dir)
  for _index_0 = 1, #names do
    local name = names[_index_0]
    local s = compiler_api.get_action_schema(name)
    if s then
      registry[name] = s
    end
  end
  return registry
end
local _condition_registry = nil
local _action_registry = nil
local conditions
conditions = function()
  _condition_registry = _condition_registry or build_condition_registry()
  return _condition_registry
end
local actions
actions = function()
  _action_registry = _action_registry or build_action_registry()
  return _action_registry
end
local reload
reload = function()
  _condition_registry = build_condition_registry()
  _action_registry = build_action_registry()
end
return {
  conditions = conditions,
  actions = actions,
  reload = reload
}
