-- src/webui/schema/registry.moon
-- Découverte automatique des conditions et actions disponibles.
-- Scanne lua/filter/conditions/ et lua/filter/actions/ et construit
-- des registres { nom → schema } incluant les variantes auto-générées.

compiler_api = require "filter.compiler_api"

-- Déduit le répertoire lua/ à partir du package.path
find_lua_dir = ->
  for p in (package.path or "")\gmatch "[^;]+"
    -- Cherche un pattern comme ".../lua/?.lua"
    dir = p\match "^(.+)/lua/%?"
    return dir .. "/lua" if dir
    -- Ou directement "lua/?.lua"
    dir = p\match "^(lua)/%?"
    return dir if dir
  "lua"

-- Liste les fichiers .lua d'un répertoire via io.popen + ls
list_lua_files = (dir) ->
  names = {}
  fh = io.popen "ls -1 '#{dir}' 2>/dev/null"
  return names unless fh
  for line in fh\lines!
    name = line\match "^(.+)%.lua$"
    names[#names + 1] = name if name and name ~= "init"
  fh\close!
  names

-- Labels pour les variantes auto-générées
variant_labels = (base_schema, variant) ->
  return nil unless base_schema
  s = {k, v for k, v in pairs base_schema}  -- shallow copy
  if variant == "plural"
    s.label = (s.label or "") .. " (plusieurs)"
    s.arg_type = "string_list"
    s.arg_hint = nil
  elseif variant == "list"
    s.label = (s.label or "") .. " (liste nommée)"
    s.arg_type = "string"
    s.arg_hint = "nom d'un fichier dans lists_dir"
  elseif variant == "lists"
    s.label = (s.label or "") .. " (plusieurs listes nommées)"
    s.arg_type = "string_list"
    s.arg_hint = nil
  s

-- Extrait le type de base depuis un nom de variante
-- "from_nets" → "from_net"
-- "from_net_list" → "from_net"
-- "from_net_lists" → "from_net"
base_of_variant = (name) ->
  b = name\match "^(.+)_lists$"
  return b if b
  b = name\match "^(.+)_list$"
  return b if b
  b = name\match "^(.+)s$"
  return b if b
  nil

variant_type = (name) ->
  return "lists" if name\match "_lists$"
  return "list"  if name\match "_list$"
  return "plural"

--- Construit le registre des conditions disponibles.
-- Inclut les modules physiques + variantes auto-générées dérivées.
-- @treturn table { nom → schema }
build_condition_registry = ->
  lua_dir = find_lua_dir!
  cond_dir = lua_dir .. "/filter/conditions"
  registry = {}

  names = list_lua_files cond_dir
  for name in *names
    s = compiler_api.get_condition_schema name
    registry[name] = s if s

  -- Variantes auto-générées à partir des modules de base uniquement
  -- Snapshot avant modification pour éviter l'itération infinie
  base_names = [name for name in pairs registry]
  for base_name in *base_names
    base_schema = registry[base_name]
    -- Pluriel (s)
    plural = base_name .. "s"
    unless registry[plural]
      s = variant_labels base_schema, "plural"
      registry[plural] = s if s

    -- Liste nommée (_list)
    list = base_name .. "_list"
    unless registry[list]
      s = variant_labels base_schema, "list"
      registry[list] = s if s

    -- Listes nommées (_lists)
    lists = base_name .. "_lists"
    unless registry[lists]
      s = variant_labels base_schema, "lists"
      registry[lists] = s if s

  registry

--- Construit le registre des actions disponibles.
-- @treturn table { nom → schema }
build_action_registry = ->
  lua_dir = find_lua_dir!
  action_dir = lua_dir .. "/filter/actions"
  registry = {}

  names = list_lua_files action_dir
  for name in *names
    s = compiler_api.get_action_schema name
    registry[name] = s if s

  registry

-- Registres initialisés une seule fois au chargement du module
_condition_registry = nil
_action_registry    = nil

--- Retourne le registre des conditions (lazy init).
conditions = ->
  _condition_registry or= build_condition_registry!
  _condition_registry

--- Retourne le registre des actions (lazy init).
actions = ->
  _action_registry or= build_action_registry!
  _action_registry

--- Force le rechargement des registres (après compilation de nouveaux modules).
reload = ->
  _condition_registry = build_condition_registry!
  _action_registry    = build_action_registry!

{ :conditions, :actions, :reload }
