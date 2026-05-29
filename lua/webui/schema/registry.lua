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
local CATEGORY_ORDER = {
  source = 1,
  destination = 2,
  time = 3,
  meta = 4
}
local CATEGORY_LABEL = {
  source = "Source (origine de la requête)",
  destination = "Destination (cible de la requête)",
  time = "Horaire",
  meta = "Méta (combinaisons)"
}
local FORM_LABELS = {
  base = "Une valeur exacte",
  plural = "Plusieurs valeurs (une par ligne)",
  list = "Une liste nommée (fichier)",
  lists = "Plusieurs listes nommées (fichiers)"
}
local FORM_SUFFIX = {
  base = "",
  plural = "s",
  list = "_list",
  lists = "_lists"
}
local FORM_ORDER = {
  "base",
  "plural",
  "list",
  "lists"
}
local is_root
is_root = function(reg, name)
  local b = base_of_variant(name)
  return not (b and reg[b])
end
local list_type_of
list_type_of = function(root)
  return root:match("^[^_]+_(.+)$")
end
local resolve_condition
resolve_condition = function(name)
  local reg = conditions()
  local b = base_of_variant(name)
  if b and reg[b] then
    return b, variant_type(name)
  else
    return name, "base"
  end
end
local condition_families
condition_families = function()
  local reg = conditions()
  local fams = { }
  for name, s in pairs(reg) do
    local _continue_0 = false
    repeat
      if not (is_root(reg, name)) then
        _continue_0 = true
        break
      end
      local meta = (s.category == "meta")
      local forms = { }
      for _index_0 = 1, #FORM_ORDER do
        local _continue_1 = false
        repeat
          local fkey = FORM_ORDER[_index_0]
          if meta and fkey ~= "base" then
            _continue_1 = true
            break
          end
          local fname = name .. FORM_SUFFIX[fkey]
          local fs = reg[fname]
          if not (fs) then
            _continue_1 = true
            break
          end
          local hint
          local _exp_0 = fkey
          if "base" == _exp_0 then
            hint = fs.arg_hint
          elseif "plural" == _exp_0 then
            hint = "une valeur par ligne"
          elseif "list" == _exp_0 then
            hint = "nom d'un fichier de liste"
          elseif "lists" == _exp_0 then
            hint = "un nom de liste par ligne"
          end
          forms[#forms + 1] = {
            key = fkey,
            name = fname,
            label = FORM_LABELS[fkey],
            description = fs.description,
            hint = hint,
            list_type = (fkey == "list" or fkey == "lists") and list_type_of(name) or nil
          }
          _continue_1 = true
        until true
        if not _continue_1 then
          break
        end
      end
      fams[#fams + 1] = {
        root = name,
        label = (s.label or name),
        category = (s.category or "z"),
        description = s.description,
        forms = forms
      }
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  table.sort(fams, function(a, b)
    local ca = CATEGORY_ORDER[a.category] or 99
    local cb = CATEGORY_ORDER[b.category] or 99
    if ca == cb then
      return a.label < b.label
    else
      return ca < cb
    end
  end)
  return fams
end
local category_label
category_label = function(cat)
  return CATEGORY_LABEL[cat] or cat
end
return {
  conditions = conditions,
  actions = actions,
  reload = reload,
  condition_families = condition_families,
  resolve_condition = resolve_condition,
  category_label = category_label
}
