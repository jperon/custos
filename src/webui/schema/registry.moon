-- src/webui/schema/registry.moon
-- Découverte automatique des conditions et actions disponibles.
-- Scanne lua/filter/conditions/ et lua/filter/actions/ et construit
-- des registres { nom → schema } incluant les variantes auto-générées.

compiler_api = require "filter.compiler_api"

-- Déduit le répertoire racine des modules Lua via package.searchpath.
find_lua_dir = ->
  path = package.searchpath "filter.conditions.from_net", package.path
  if path
    dir = path\match "^(.+)/filter/conditions/from_net%.lua$"
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

-- ── Familles de conditions (pour l'UI à deux dropdowns) ────────────────────
-- Une « famille » regroupe une condition de base et ses variantes
-- (une valeur / plusieurs valeurs / liste nommée / plusieurs listes).
-- Ex. famille « to_domain » → to_domain, to_domains, to_domain_list, to_domain_lists.

CATEGORY_ORDER = { source: 1, destination: 2, time: 3, meta: 4 }
CATEGORY_LABEL = {
  source:      "Source (origine de la requête)"
  destination: "Destination (cible de la requête)"
  time:        "Horaire"
  meta:        "Méta (combinaisons)"
}
FORM_LABELS = {
  base:   "Une valeur exacte"
  plural: "Plusieurs valeurs (une par ligne)"
  list:   "Une liste nommée (fichier)"
  lists:  "Plusieurs listes nommées (fichiers)"
}
FORM_SUFFIX  = { base: "", plural: "s", list: "_list", lists: "_lists" }
FORM_ORDER   = { "base", "plural", "list", "lists" }

-- Un nom est racine s'il ne dérive pas d'une autre condition du registre.
is_root = (reg, name) ->
  b = base_of_variant name
  not (b and reg[b])

-- Sous-répertoire de listes associé à une racine : "to_domain" → "domain".
list_type_of = (root) -> root\match "^[^_]+_(.+)$"

--- Résout un nom de condition stocké en (racine, forme).
-- @tparam string name Nom réel (ex. "to_domain_lists", "to_domains", "from_net")
-- @treturn string,string racine, clé de forme ("base"|"plural"|"list"|"lists")
resolve_condition = (name) ->
  reg = conditions!
  b = base_of_variant name
  if b and reg[b]
    b, variant_type name
  else
    name, "base"

--- Construit la liste ordonnée des familles de conditions.
-- @treturn table tableau de { root, label, category, description, forms }
--   forms = tableau ordonné de { key, name, label, description, hint, list_type }
condition_families = ->
  reg = conditions!
  fams = {}
  for name, s in pairs reg
    continue unless is_root reg, name
    meta = (s.category == "meta")
    forms = {}
    for fkey in *FORM_ORDER
      -- Les méta-conditions n'ont pas de variantes pertinentes.
      continue if meta and fkey != "base"
      fname = name .. FORM_SUFFIX[fkey]
      fs = reg[fname]
      continue unless fs
      -- Override optionnel par condition (s.forms[fkey]) : libellé/hint/description
      -- spécifiques (ex. « Groupe de listes » pour to_domainlist). Sinon valeurs
      -- génériques partagées par toutes les conditions.
      ovr = s.forms and s.forms[fkey]
      hint = (ovr and ovr.hint) or switch fkey
        when "base"   then fs.arg_hint
        when "plural" then "une valeur par ligne"
        when "list"   then "nom d'un fichier de liste"
        when "lists"  then "un nom de liste par ligne"
      forms[#forms + 1] = {
        key:         fkey
        name:        fname
        label:       (ovr and ovr.label) or FORM_LABELS[fkey]
        description: (ovr and ovr.description) or fs.description
        hint:        hint
        list_type:   (fkey == "list" or fkey == "lists") and list_type_of(name) or nil
      }
    fams[#fams + 1] = {
      root:        name
      label:       (s.label or name)
      category:    (s.category or "z")
      description: s.description
      :forms
    }
  table.sort fams, (a, b) ->
    ca = CATEGORY_ORDER[a.category] or 99
    cb = CATEGORY_ORDER[b.category] or 99
    if ca == cb then a.label < b.label else ca < cb
  fams

--- Libellé lisible d'une catégorie (pour les optgroups).
category_label = (cat) -> CATEGORY_LABEL[cat] or cat

{ :conditions, :actions, :reload, :condition_families, :resolve_condition,
  :category_label }
