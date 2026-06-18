-- src/webui/handlers/lists.moon
-- Éditeur de fichiers de listes (from_xxx_list).
-- Structure : {lists_dir}/{type}/{name}.txt — un élément par ligne.
--
-- GET  /admin/config/filter/lists              — index des types
-- GET  /admin/config/filter/lists/:type        — liste des fichiers d'un type
-- GET  /admin/config/filter/lists/:type/new    — formulaire de création
-- POST /admin/config/filter/lists/:type/new    — création
-- GET  /admin/config/filter/lists/:type/:name  — édition
-- POST /admin/config/filter/lists/:type/:name  — enregistrement, renommage ou suppression

H       = require "auth.html"
{ :page } = require "webui.handlers.dashboard"
{ :read_config, :write_config } = require "webui.serializer"
{ :shquote } = require "lib.shquote"

parse_form = (body) ->
  return {} unless body
  out = {}
  dec = (s) -> (s\gsub "%%(%x%x)", (h) -> string.char tonumber h, 16)\gsub "+", " "
  for k, v in body\gmatch "([^&=]+)=([^&]*)"
    out[dec k] = dec v
  out

valid_type = (t) -> t and t\match "^[a-z][a-z0-9_]*$"
valid_name = (n) -> n and n\match "^[a-zA-Z0-9][a-zA-Z0-9_%-]*$"

get_lists_dir = (state) ->
  cfg = read_config state.config_path
  dir = cfg and cfg.filter and cfg.filter.lists_dir
  dir = dir or (cfg and cfg.lists_dir)
  dir or "/tmp/custos/lists"

-- Lister les sous-répertoires (types) dans lists_dir
scan_types = (lists_dir) ->
  types = {}
  f = io.popen "find #{shquote lists_dir} -maxdepth 1 -mindepth 1 -type d 2>/dev/null"
  return types unless f
  for line in f\lines!
    t = line\match "/([^/]+)$"
    types[#types + 1] = t if valid_type t
  f\close!
  table.sort types
  types

-- Lister les fichiers .txt dans un sous-répertoire de type
scan_names = (lists_dir, type_name) ->
  names = {}
  dir = "#{lists_dir}/#{type_name}"
  f = io.popen "find #{shquote dir} -maxdepth 1 -name '*.txt' -type f 2>/dev/null"
  return names unless f
  for line in f\lines!
    n = line\match "/([^/]+)%.txt$"
    names[#names + 1] = n if valid_name n
  f\close!
  table.sort names
  names

read_list_file = (path) ->
  fh = io.open path, "r"
  return "" unless fh
  content = fh\read "*a"
  fh\close!
  content

write_list_file = (path, content) ->
  dir = path\match "^(.*)/[^/]+$"
  if dir
    ret = os.execute "mkdir -p #{shquote dir}"
    return nil, "mkdir échoué" unless ret == 0 or ret == true
  fh = io.open path, "w"
  return nil, "Impossible d'ouvrir #{path} en écriture" unless fh
  fh\write content
  fh\close!
  true

-- Met à jour les références à old_name → new_name dans les conditions des règles.
-- Cherche toutes les clés de conditions se terminant par _{type_name}_list(s).
-- Retourne true si au moins une référence a été modifiée.
update_config_refs = (cfg, type_name, old_name, new_name) ->
  changed = false
  rules = cfg.filter and cfg.filter.rules
  return false unless rules
  suffix_single = "_#{type_name}_list"
  suffix_multi  = "_#{type_name}_lists"
  for rule in *rules
    conds = rule.conditions
    continue unless conds
    for ckey, cval in pairs conds
      if ckey\match(suffix_single .. "$") or ckey\match(suffix_multi .. "$")
        if type(cval) == "string" and cval == old_name
          conds[ckey] = new_name
          changed = true
        elseif type(cval) == "table"
          for i, v in ipairs cval
            if v == old_name
              cval[i] = new_name
              changed = true
  changed

-- ── Index des types ──────────────────────────────────────────────────────

handle_lists_index = (req, state) ->
  lists_dir = get_lists_dir state
  types = scan_types lists_dir

  items = ""
  for t in *types
    names = scan_names lists_dir, t
    n = #names
    items ..= H.li {
      H.a { href: "/admin/config/filter/lists/#{t}" }, t
      " — #{n} liste#{n > 1 and 's' or ''}"
    }

  body = H.section {
    H.h2 "Listes de filtrage"
    H.p { style: "color:#555" }, "Répertoire : " .. H.code(lists_dir)
    H.p { style: "color:#555" }, "Une liste regroupe des valeurs (un domaine, un réseau… par ligne) que vous pouvez réutiliser dans vos règles. Dans l'éditeur de règles, choisissez une condition puis la forme « Une liste nommée » et indiquez le nom de la liste."
    H.p { style: "color:#555" }, "Les listes sont rangées par type de condition (domaine, réseau, mac…). Exemple : créez une liste « malware » de type « domaine », puis utilisez-la dans une règle « Domaine cible » → « Une liste nommée »."
    if items ~= ""
      H.ul {}, items
    else
      H.p "Aucun type trouvé dans " .. H.code(lists_dir) .. "."
    H.p { H.a { class: "btn btn-secondary", href: "/admin/config/" }, "← Configuration" }
  }
  200, { ["Content-Type"]: "text/html; charset=UTF-8" }, page "Listes de filtrage", body

-- ── Liste des fichiers d'un type ─────────────────────────────────────────

handle_lists_type = (req, type_name, state) ->
  return 400, {}, "Type invalide" unless valid_type type_name
  lists_dir = get_lists_dir state
  names = scan_names lists_dir, type_name

  rows = ""
  for n in *names
    rows ..= H.tr {
      H.td { H.a { href: "/admin/config/filter/lists/#{type_name}/#{n}" }, n .. ".txt" }
      H.td {
        H.form { method: "POST", action: "/admin/config/filter/lists/#{type_name}/#{n}",
                 style: "display:inline" }, {
          H.input { type: "hidden", name: "action", value: "delete" }
          H.button { type: "submit", class: "btn btn-danger btn-sm",
                     onclick: "return confirm('Supprimer ?')" }, "✕"
        }
      }
    }

  tbl = if rows ~= ""
    H.table {
      H.thead { H.tr { H.th "Fichier", H.th "" } }
      H.tbody {}, rows
    }
  else
    H.p "Aucune liste pour ce type."

  body = H.section {
    H.h2 "Listes — #{type_name}"
    H.p { H.a { class: "btn btn-secondary", href: "/admin/config/filter/lists/#{type_name}/new" },
          "+ Nouvelle liste" }
    tbl
    H.p { style: "margin-top:1rem" }, {
      H.a { class: "btn btn-secondary", href: "/admin/config/filter/lists" }, "← Retour"
    }
  }
  200, { ["Content-Type"]: "text/html; charset=UTF-8" }, page "Listes — #{type_name}", body

-- ── Édition d'une liste ──────────────────────────────────────────────────

handle_list_get = (req, type_name, list_name, state) ->
  return 400, {}, "Type invalide" unless valid_type type_name
  return 400, {}, "Nom invalide"  unless valid_name list_name
  lists_dir = get_lists_dir state
  path = "#{lists_dir}/#{type_name}/#{list_name}.txt"
  content = read_list_file path
  base_url = "/admin/config/filter/lists/#{type_name}/#{list_name}"

  item_hint = if type_name == "domainlist"
    "un nom de domainlist par ligne — ce fichier-groupe référence d'autres listes"
  else
    "un élément par ligne"
  edit_body = H.div({
      H.label "Contenu (#{item_hint} — les lignes vides et # commentaires sont ignorés)"
      H.textarea { name: "content", rows: "20",
                   style: "font-family:monospace;width:100%;margin-top:.25rem" }, content
    }) ..
    H.input({ type: "hidden", name: "action", value: "save" }) ..
    H.div({ style: "margin-top:.75rem" },
      H.button({ type: "submit" }, "Enregistrer") ..
      " " ..
      H.a({ class: "btn btn-secondary",
            href: "/admin/config/filter/lists/#{type_name}" }, "Annuler"))
  edit_form = H.form { method: "POST", action: base_url }, edit_body

  rename_inner = H.div({ style: "display:flex;gap:.5rem;align-items:flex-end" },
      H.div({
          H.label "Nouveau nom"
          H.input { type: "text", name: "new_name", value: list_name,
                    pattern: "[a-zA-Z0-9][a-zA-Z0-9_\\-]*", required: "required" }
        }) ..
      H.div({ },
        H.input({ type: "hidden", name: "action", value: "rename" }) ..
        H.button({ type: "submit" }, "Renommer"))) ..
    H.p({ style: "color:#888;font-size:.85em;margin:.25rem 0 0" },
      "Les références dans config.moon seront mises à jour automatiquement.")
  rename_form = H.details({
    H.summary({ style: "cursor:pointer;color:#555;margin-top:1.5rem" }, "Renommer cette liste") ..
    H.form({ method: "POST", action: base_url, style: "margin-top:.5rem" }, rename_inner)
  })

  body = H.section {
    H.h2 "#{type_name} / #{list_name}.txt"
    edit_form
    rename_form
  }
  200, { ["Content-Type"]: "text/html; charset=UTF-8" }, page "#{type_name}/#{list_name}", body

handle_list_post = (req, type_name, list_name, state) ->
  return 400, {}, "Type invalide" unless valid_type type_name
  return 400, {}, "Nom invalide"  unless valid_name list_name
  form = parse_form req.body
  lists_dir = get_lists_dir state
  path = "#{lists_dir}/#{type_name}/#{list_name}.txt"

  if form.action == "delete"
    os.remove path
    return 302, { ["Location"]: "/admin/config/filter/lists/#{type_name}" }, ""

  if form.action == "rename"
    new_name = form.new_name and (form.new_name\match "^%s*(.-)%s*$") or ""
    return 400, {}, "Nouveau nom invalide" unless valid_name new_name
    return 302, { ["Location"]: "/admin/config/filter/lists/#{type_name}/#{list_name}" }, "" if new_name == list_name
    new_path = "#{lists_dir}/#{type_name}/#{new_name}.txt"
    ret = os.rename path, new_path
    return 500, {}, "Échec du renommage de #{list_name} → #{new_name}" unless ret
    -- Mise à jour des références dans config.moon (best-effort)
    cfg, _ = read_config state.config_path
    if cfg
      changed = update_config_refs cfg, type_name, list_name, new_name
      write_config cfg, state.config_path if changed
    return 302, { ["Location"]: "/admin/config/filter/lists/#{type_name}/#{new_name}" }, ""

  content = form.content or ""
  ok, e = write_list_file path, content
  return 500, {}, "Erreur écriture : #{e}" unless ok
  302, { ["Location"]: "/admin/config/filter/lists/#{type_name}/#{list_name}" }, ""

-- ── Création d'une nouvelle liste ────────────────────────────────────────

handle_list_new_get = (req, type_name, state) ->
  return 400, {}, "Type invalide" unless valid_type type_name
  body = H.section {
    H.h2 "Nouvelle liste — #{type_name}"
    H.form { method: "POST", action: "/admin/config/filter/lists/#{type_name}/new" }, {
      H.div {
        H.label "Nom (lettres, chiffres, - et _ uniquement)"
        H.input { type: "text", name: "name", placeholder: "ex: famille", required: "required" }
      }
      H.div {
        H.label "Contenu (un élément par ligne)"
        H.textarea { name: "content", rows: "10",
                     style: "font-family:monospace;width:100%;margin-top:.25rem" }, ""
      }
      H.div { style: "margin-top:.75rem" }, {
        H.button { type: "submit" }, "Créer"
        " "
        H.a { class: "btn btn-secondary",
              href: "/admin/config/filter/lists/#{type_name}" }, "Annuler"
      }
    }
  }
  200, { ["Content-Type"]: "text/html; charset=UTF-8" }, page "Nouvelle liste — #{type_name}", body

handle_list_new_post = (req, type_name, state) ->
  return 400, {}, "Type invalide" unless valid_type type_name
  form = parse_form req.body
  list_name = form.name and (form.name\match "^%s*(.-)%s*$") or ""
  return 400, {}, "Nom invalide" unless valid_name list_name
  lists_dir = get_lists_dir state
  path = "#{lists_dir}/#{type_name}/#{list_name}.txt"
  content = form.content or ""
  ok, e = write_list_file path, content
  return 500, {}, "Erreur écriture : #{e}" unless ok
  302, { ["Location"]: "/admin/config/filter/lists/#{type_name}/#{list_name}" }, ""

{
  :handle_lists_index
  :handle_lists_type
  :handle_list_get,     :handle_list_post
  :handle_list_new_get, :handle_list_new_post
}
