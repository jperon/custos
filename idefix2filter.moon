#!/usr/bin/env moon
--- Script de migration Idefix3 -> CustosVirginum.
-- Usage (depuis la racine du dépôt, après `make all`) :
--   luajit idefix2filter.lua <idefix.json> <dossier-sortie>
--
-- Écrit <dossier-sortie>/config.moon, <dossier-sortie>/listes/*.domains et
-- <dossier-sortie>/listes/custom/*.domains.
--
-- Le JSON est décodé par lib.json (src/lib/json.moon → lua/lib/json.lua).
-- La logique pure (collecte, règles, rendu) est exportée pour
-- tests/unit/idefix2filter_spec.moon ; main! n'est lancé que si le script est
-- exécuté directement (même motif que install-owrt.moon).

package.path = table.concat {
  "lua/?.lua"
  "lua/?/init.lua"
  "lua/?/?.lua"
  package.path
}, ";"

json = require "lib.json"

-- Groupes de devices produits par Idefix (lus dans data.maclists).
MACLIST_GROUPS = { "profs", "abbes", "eleves_limites", "salon_profs", "defaut" }

-- Noms de profils Idefix associés à un groupe de devices.
PROFILE_MAP = {
  ["Internet autorisé (filtré par catégories \"large\")"]: "profs"
  ["Internet filtré par défaut (prieuré)"]: "defaut"
  ["Internet limité (liste blanche)"]: "eleves_limites"
}

-- Domainlists utilisées par les règles de profil (chemins relatifs à
-- filter.domainlists_dir, cf. src/filter/conditions/to_domainlist.moon:234).
ABBES_LISTS = {
  "custom/addenda_religieux"
  "custom/addenda_auth"
  "custom/addenda_banque"
  "custom/addenda_cloud"
  "custom/addenda_communication"
  "custom/addenda_courriel"
  "custom/addenda_gps"
  "custom/addenda_maj"
  "custom/addenda_peripheriques"
  "custom/addenda_stemarie"
  "custom/default_fsspx"
  "custom/limite_eleves_fsspx"
}

ELEVES_LISTS = {
  "custom/addenda_apple"
  "custom/addenda_cloud"
  "custom/addenda_courriel"
  "custom/addenda_maj"
  "custom/addenda_peripheriques"
  "custom/addenda_stemarie"
  "custom/default_fsspx"
  "custom/limite_eleves_fsspx"
}

--- Nettoie un domaine Idefix (espaces, préfixe « *. », minuscules).
-- @tparam string domain Domaine brut
-- @treturn string|nil Domaine normalisé, ou nil si vide
clean_domain = (domain) ->
  return nil unless domain
  domain = domain\gsub "^%s*(.-)%s*$", "%1"
  return nil if domain == ""
  domain = domain\gsub "^%*. ", ""
  domain\lower!

--- Nettoie et trie une liste de domaines.
clean_domains = (domains) ->
  cleaned = {}
  for d in *domains
    c = clean_domain d
    table.insert cleaned, c if c
  table.sort cleaned
  cleaned

ESCAPES = {
  '"': '\\"'
  "\\": "\\\\"
  "\n": "\\n"
  "\r": "\\r"
  "\t": "\\t"
}

--- Rend une chaîne comme littéral Lua/MoonScript doublement quoté.
escape_string = (s) ->
  '"' .. (tostring(s)\gsub '[%c"\\]', (c) -> ESCAPES[c] or string.format "\\%03d", c\byte!) .. '"'

--- Rend une liste de chaînes comme table MoonScript.
render_array = (items) ->
  "{" .. table.concat([escape_string item for item in *items], ", ") .. "}"

-- Une condition vaut soit une chaîne, soit une liste (cf. cfg/config.moon:28).
render_condition = (value) ->
  if type(value) == "table"
    render_array value
  else
    escape_string value

-- ── Extraction depuis le JSON Idefix ────────────────────────────────

--- Listes de domaines par groupe (`data.groups.*.dest_domains`).
collect_group_lists = (data) ->
  lists = {}
  groups = data.groups or {}
  for group_name, group_data in pairs groups
    continue unless type(group_data) == "table"
    domains = group_data.dest_domains or {}
    cleaned = clean_domains domains
    lists[group_name] = cleaned if #cleaned > 0
  lists

--- Listes spéciales block_yahoo et spotify (`data.rules[…].dest_domains`).
collect_special_lists = (data) ->
  specials = {}
  rules = data.rules or {}
  yahoo = rules["block yahoo search"]
  if yahoo
    cleaned = clean_domains yahoo.dest_domains or {}
    specials.block_yahoo = cleaned if #cleaned > 0
  spotify = rules["Salon profs"]
  if spotify
    cleaned = clean_domains spotify.dest_domains or {}
    specials.spotify = cleaned if #cleaned > 0
  specials

has_member = (list, value) ->
  for item in *list
    return true if item == value
  false

--- Associe chaque device à sa MAC et à son groupe (cf. data.users).
-- Les overrides « Salon profs » / « Abbés » sont appliqués comme dans le
-- script d'origine.
collect_macs_and_lists = (data) ->
  macs = {}
  maclists = {}
  input_lists = data.maclists or {}
  for name in *MACLIST_GROUPS
    maclists[name] = {}
    for member in *(input_lists[name] or {})
      table.insert maclists[name], member

  users = data.users or {}
  for profile_name, profile_data in pairs users
    continue unless type(profile_data) == "table"
    group_key = PROFILE_MAP[profile_name]
    for user_key, user_data in pairs profile_data
      continue unless type(user_data) == "table" and user_data.devices
      for dev_name, dev_data in pairs user_data.devices
        continue unless type(dev_data) == "table"
        mac = dev_data.mac
        continue unless mac
        macs[dev_name] = mac
        target = group_key
        if user_key == "Salon profs"
          target = "salon_profs"
        elseif user_key == "Abbés"
          target = "abbes"
        if target
          members = maclists[target]
          table.insert members, dev_name unless has_member members, dev_name

  for name in *MACLIST_GROUPS
    table.sort maclists[name]
  macs, maclists

--- Construit une règle Custos.
rule = (description, action, conditions) ->
  {
    description: description
    actions: { action }
    conditions: conditions or {}
  }

--- Construit les règles de migration à partir des groupes collectés.
-- Les clés émises existent dans le code du filtre :
--   to_domainlist  → src/filter/conditions/to_domainlist.moon
--   to_domainlists → src/filter/conditions/to_domainlists.moon
--   to_domains     → src/filter/conditions/to_domains.moon
--   from_macs      → variante plurielle de src/filter/conditions/from_mac.moon
--                    (générée par src/filter/compiler_api.moon:244)
build_rules = (maclists, specials) ->
  rules = {}
  if specials.block_yahoo
    rules[#rules + 1] = rule "Blocages prioritaires", "deny", {
      to_domainlist: "custom/block_yahoo"
    }
  unless #maclists.profs == 0
    rules[#rules + 1] = rule "Accès total Profs", "allow", {
      from_macs: maclists.profs
    }
  rules[#rules + 1] = rule "Infrastructure et local", "allow", {
    to_domains: { "local", "lan", "home.arpa" }
  }
  unless #maclists.abbes == 0
    rules[#rules + 1] = rule "Profil Abbés", "allow", {
      from_macs: maclists.abbes
      to_domainlists: ABBES_LISTS
    }
  unless #maclists.eleves_limites == 0
    rules[#rules + 1] = rule "Profil Élèves Limités", "allow", {
      from_macs: maclists.eleves_limites
      to_domainlists: ELEVES_LISTS
    }
  if specials.spotify and #maclists.salon_profs > 0
    rules[#rules + 1] = rule "Spotify Salon Profs", "allow", {
      from_macs: maclists.salon_profs
      to_domainlist: "custom/spotify"
    }
  rules[#rules + 1] = rule "Verdict Final", "deny", {}
  rules

--- Rend la configuration Custos en MoonScript valide.
render_config = (macs, rules) ->
  lines = {
    "-- Généré par idefix2filter.moon"
    ""
    "filter:"
    '  domainlists_dir: "/etc/custos/lists"'
    '  custom_lists_dir: "/etc/custos/lists/custom"'
  }

  mac_keys = [k for k in pairs macs]
  table.sort mac_keys
  if #mac_keys > 0
    lines[#lines + 1] = ""
    lines[#lines + 1] = "  macs:"
    for key in *mac_keys
      lines[#lines + 1] = "    #{escape_string key}: #{escape_string macs[key]}"

  lines[#lines + 1] = ""
  lines[#lines + 1] = "  rules: {"
  for r in *rules
    lines[#lines + 1] = "    {"
    lines[#lines + 1] = "      description: #{escape_string r.description}"
    lines[#lines + 1] = "      actions: #{render_array r.actions}"
    condition_keys = [k for k in pairs r.conditions]
    table.sort condition_keys
    if #condition_keys > 0
      lines[#lines + 1] = "      conditions:"
      for key in *condition_keys
        lines[#lines + 1] = "        #{key}: #{render_condition r.conditions[key]}"
    else
      lines[#lines + 1] = "      conditions: {}"
    lines[#lines + 1] = "    }"
  lines[#lines + 1] = "  }"
  table.concat(lines, "\n") .. "\n"

--- Convertit la table JSON Idefix en listes, règles et config MoonScript.
convert = (data) ->
  lists = collect_group_lists data
  specials = collect_special_lists data
  macs, maclists = collect_macs_and_lists data
  rules = build_rules maclists, specials
  config = render_config macs, rules
  :lists, :specials, :macs, :maclists, :rules, :config

-- ── I/O ─────────────────────────────────────────────────────────────

sh_quote = (s) ->
  "'" .. (tostring(s)\gsub "'", "'\\''") .. "'"

ensure_dir = (path) ->
  os.execute "mkdir -p #{sh_quote path}"

write_file = (path, content) ->
  f = assert io.open path, "w"
  f\write content
  f\close!

--- Écrit les listes de domaines (format texte lu par to_domainlist :
-- `.bin` sinon `.domains`, cf. src/filter/conditions/to_domainlist.moon:234).
write_lists = (cfg_dir, out) ->
  base = "#{cfg_dir}/listes"
  ensure_dir base
  group_names = [name for name in pairs out.lists]
  table.sort group_names
  for name in *group_names
    write_file "#{base}/#{name}.domains", (table.concat out.lists[name], "\n") .. "\n"

  custom = "#{base}/custom"
  ensure_dir custom
  special_names = [name for name in pairs out.specials]
  table.sort special_names
  for name in *special_names
    write_file "#{custom}/#{name}.domains", (table.concat out.specials[name], "\n") .. "\n"

--- Charge le JSON, convertit, puis écrit config.moon et les listes.
run = (idefix_path, cfg_dir) ->
  f = io.open idefix_path, "r"
  error "impossible d'ouvrir #{idefix_path}" unless f
  content = f\read "*a"
  f\close!
  data = json.decode content
  out = convert data
  ensure_dir cfg_dir
  write_lists cfg_dir, out
  write_file "#{cfg_dir}/config.moon", out.config
  out

main = (args=arg) ->
  idefix = args and args[1]
  cfg = args and args[2]
  unless idefix and cfg
    io.stderr\write "Usage : luajit idefix2filter.lua <idefix.json> <dossier-sortie>\n"
    os.exit 1
  run idefix, cfg
  io.write "Configuration écrite dans #{cfg}/config.moon\n"

-- N'exécute main! que lancé directement comme script (pas quand les tests
-- unitaires chargent le fichier compilé).
script_name = arg and arg[0] or ""
main! if script_name\match "idefix2filter"

{ :clean_domain, :clean_domains, :collect_group_lists, :collect_special_lists,
  :collect_macs_and_lists, :build_rules, :render_config, :convert,
  :write_lists, :run, :main }
