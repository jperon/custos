-- src/webui/handlers/filter.moon
-- GET/POST /admin/config/filter/nets|macs|times|users|decision
-- Édition des dictionnaires nommés du filtre DNS.

H       = require "auth.html"
{ :css } = require "webui.css"
{ :page } = require "webui.handlers.dashboard"
{ :read_config, :write_config } = require "webui.serializer"

parse_form = (body) ->
  return {} unless body
  out = {}
  dec = (s) -> (s\gsub "%%(%x%x)", (h) -> string.char tonumber h, 16)\gsub "+", " "
  for k, v in body\gmatch "([^&=]+)=([^&]*)"
    out[dec k] = dec v
  out

-- ── Éditeur de table clé→valeur (nets, macs, users) ──────────────────────

render_kv_editor = (section_key, title, desc, value_label, current_map, value_hint) ->
  rows = ""
  if current_map
    for k, v in pairs current_map
      val_str = if type(v) == "table" then table.concat v, "\n" else tostring v
      rows ..= H.tr {
        H.td { H.input { type: "text", name: "key[]", value: k, style: "margin:0" } }
        H.td { H.textarea { name: "val[]", rows: "2", style: "margin:0; font-family:monospace" }, val_str }
        H.td { H.button { type: "submit", name: "delete", value: k, class: "btn btn-danger btn-sm" }, "✕" }
      }

  -- Ligne d'ajout
  rows ..= H.tr {
    H.td { H.input { type: "text",     name: "newkey",  placeholder: "nouveau nom" } }
    H.td { H.textarea { name: "newval", rows: "2", placeholder: value_hint or "valeur" }, "" }
    H.td ""
  }

  H.section {
    H.h2 title
    H.p { style: "color:#555" }, desc
    H.form { method: "POST", action: "/admin/config/filter/#{section_key}" },
      H.table {
        H.thead { H.tr { H.th "Nom", H.th value_label, H.th "" } }
        H.tbody {}, rows
      }
      H.div { style: "margin-top:.75rem" },
        H.button { type: "submit", name: "action", value: "save" }, "Enregistrer"
        " "
        H.a { class: "btn btn-secondary", href: "/admin/config/" }, "Annuler"
  }

-- ── Éditeur plages horaires ───────────────────────────────────────────────

render_times_editor = (current_times) ->
  rows = ""
  if current_times
    for k, v in pairs current_times
      start_s = type(v) == "table" and (v[1] or "") or ""
      end_s   = type(v) == "table" and (v[2] or "") or ""
      rows ..= H.tr {
        H.td { H.input { type: "text", name: "key[]", value: k } }
        H.td { H.input { type: "time", name: "start[]", value: start_s } }
        H.td { H.input { type: "time", name: "end[]",   value: end_s } }
        H.td { H.button { type: "submit", name: "delete", value: k, class: "btn btn-danger btn-sm" }, "✕" }
      }

  rows ..= H.tr {
    H.td { H.input { type: "text", name: "newkey",   placeholder: "nom" } }
    H.td { H.input { type: "time", name: "newstart", placeholder: "08:00" } }
    H.td { H.input { type: "time", name: "newend",   placeholder: "18:00" } }
    H.td ""
  }

  H.section {
    H.h2 "Plages horaires"
    H.p { style: "color:#555" }, "Définissez des fenêtres horaires réutilisables dans les règles."
    H.form { method: "POST", action: "/admin/config/filter/times" },
      H.table {
        H.thead { H.tr { H.th "Nom", H.th "Début", H.th "Fin", H.th "" } }
        H.tbody {}, rows
      }
      H.div { style: "margin-top:.75rem" },
        H.button { type: "submit", name: "action", value: "save" }, "Enregistrer"
        " "
        H.a { class: "btn btn-secondary", href: "/admin/config/" }, "Annuler"
  }

-- ── Handlers GET ────────────────────────────────────────────────────────

make_get = (section_key, title, desc, value_label, value_hint) ->
  (req, state) ->
    cfg, err = read_config state.config_path
    return 500, {}, "Erreur config : #{err}" unless cfg
    current = (cfg.filter or {})[section_key] or {}
    section_title = "Filtre — #{title}"
    if section_key == "times"
      body = render_times_editor current
    else
      body = render_kv_editor section_key, title, desc, value_label, current, value_hint
    200, { ["Content-Type"]: "text/html; charset=UTF-8" }, page section_title, body

handle_nets_get   = make_get "nets",   "Réseaux nommés",        "Groupes de CIDRs IPv4/IPv6 réutilisables dans les conditions.", "CIDRs (un par ligne)", "ex: 192.168.0.0/16"
handle_macs_get   = make_get "macs",   "MACs nommées",          "Groupes d'adresses MAC réutilisables.",                         "MACs (une par ligne)",  "ex: aa:bb:cc:dd:ee:ff"
handle_users_get  = make_get "users",  "Utilisateurs",          "Associe un alias court à un email d'authentification.",        "Email",                 "ex: alice@example.com"
handle_times_get  = (req, state) ->
  cfg, err = read_config state.config_path
  return 500, {}, "Erreur config : #{err}" unless cfg
  current = (cfg.filter or {}).times or {}
  body = render_times_editor current
  200, { ["Content-Type"]: "text/html; charset=UTF-8" }, page "Filtre — Plages horaires", body

-- ── Handlers POST ───────────────────────────────────────────────────────

-- Reconstruit une table associative depuis les champs key[]/val[]
rebuild_kv = (form, is_list_value) ->
  keys = {}
  vals = {}
  -- Collectionner tous les key[] et val[]
  -- Les champs sont encodés comme key%5B%5D (key[]) et val%5B%5D
  -- Après décodage par parse_form ils deviennent "key[]" et "val[]"
  -- mais parse_form garde uniquement la dernière valeur pour les clés dupliquées.
  -- On re-parse le body pour extraire les listes.
  result = {}
  -- Simple : utiliser les champs déjà parsés (la dernière valeur gagne
  -- si plusieurs valeurs — ce qui arrive avec les champs [])
  -- Pour une implémentation correcte des tableaux, il faudrait un parser multipart.
  -- On utilise ici une approche simplifiée suffisante pour les dictionnaires.
  k = form["key[]"]
  v = form["val[]"]
  if k and v
    k_trim = k\match "^%s*(.-)%s*$"
    if k_trim ~= ""
      if is_list_value
        items = {}
        for line in v\gmatch "[^\n]+"
          line = line\match "^%s*(.-)%s*$"
          items[#items + 1] = line unless line == ""
        result[k_trim] = items
      else
        result[k_trim] = v\match "^%s*(.-)%s*$"
  result

make_post = (section_key, is_list_value) ->
  (req, state) ->
    form = parse_form req.body
    cfg, err = read_config state.config_path
    return 500, {}, "Erreur config : #{err}" unless cfg
    cfg.filter or= {}
    current = cfg.filter[section_key] or {}

    -- Suppression d'une entrée
    if form.delete
      current[form.delete] = nil
      cfg.filter[section_key] = current
      ok, e = write_config cfg, state.config_path
      return 500, {}, "Erreur écriture : #{e}" unless ok
      return 302, { ["Location"]: "/admin/config/filter/#{section_key}" }, ""

    -- Ajout d'une nouvelle entrée
    if form.newkey and form.newkey\match "%S"
      new_k = form.newkey\match "^%s*(.-)%s*$"
      new_v = form.newval or ""
      if is_list_value
        items = {}
        for line in new_v\gmatch "[^\n]+"
          line = line\match "^%s*(.-)%s*$"
          items[#items + 1] = line unless line == ""
        current[new_k] = items if #items > 0
      else
        current[new_k] = new_v\match "^%s*(.-)%s*$"

    cfg.filter[section_key] = current
    ok, e = write_config cfg, state.config_path
    return 500, {}, "Erreur écriture : #{e}" unless ok
    302, { ["Location"]: "/admin/config/filter/#{section_key}" }, ""

handle_nets_post  = make_post "nets",  true
handle_macs_post  = make_post "macs",  true
handle_users_post = make_post "users", false

handle_times_post = (req, state) ->
  form = parse_form req.body
  cfg, err = read_config state.config_path
  return 500, {}, "Erreur config : #{err}" unless cfg
  cfg.filter or= {}
  current = cfg.filter.times or {}

  if form.delete
    current[form.delete] = nil
    cfg.filter.times = current
    ok, e = write_config cfg, state.config_path
    return 500, {}, "Erreur écriture : #{e}" unless ok
    return 302, { ["Location"]: "/admin/config/filter/times" }, ""

  if form.newkey and form.newkey\match "%S"
    k = form.newkey\match "^%s*(.-)%s*$"
    current[k] = { form.newstart or "00:00", form.newend or "00:00" }

  cfg.filter.times = current
  ok, e = write_config cfg, state.config_path
  return 500, {}, "Erreur écriture : #{e}" unless ok
  302, { ["Location"]: "/admin/config/filter/times" }, ""

-- ── Decision ────────────────────────────────────────────────────────────

handle_decision_get = (req, state) ->
  cfg, err = read_config state.config_path
  return 500, {}, "Erreur config : #{err}" unless cfg
  d = (cfg.filter or {}).decision or {}
  body = H.section {
    H.h2 "Politique de décision"
    H.form { method: "POST", action: "/admin/config/filter/decision" },
      H.div {
        H.label "Première règle gagne (first-match)"
        H.input { type: "checkbox", name: "fmw", value: "1", checked: (d.first_match_wins != false) and "checked" or nil }
        H.input { type: "hidden", name: "fmw_present", value: "1" }
      }
      H.div {
        H.label "Continuer après match"
        H.input { type: "checkbox", name: "ctn", value: "1", checked: d.continue_to_next_rule and "checked" or nil }
        H.input { type: "hidden", name: "ctn_present", value: "1" }
      }
      H.div { style: "margin-top:.75rem" },
        H.button { type: "submit" }, "Enregistrer"
  }
  200, { ["Content-Type"]: "text/html; charset=UTF-8" }, page "Filtre — Décision", body

handle_decision_post = (req, state) ->
  form = parse_form req.body
  cfg, err = read_config state.config_path
  return 500, {}, "Erreur config : #{err}" unless cfg
  cfg.filter or= {}
  cfg.filter.decision or= {}
  cfg.filter.decision.first_match_wins      = form.fmw == "1"
  cfg.filter.decision.continue_to_next_rule = form.ctn == "1"
  ok, e = write_config cfg, state.config_path
  return 500, {}, "Erreur écriture : #{e}" unless ok
  302, { ["Location"]: "/admin/config/filter/decision" }, ""

{
  :handle_nets_get,   :handle_nets_post
  :handle_macs_get,   :handle_macs_post
  :handle_users_get,  :handle_users_post
  :handle_times_get,  :handle_times_post
  :handle_decision_get, :handle_decision_post
}
