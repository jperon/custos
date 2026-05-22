-- src/webui/handlers/rules.moon
-- Éditeur de règles de filtrage DNS.
-- GET  /admin/config/filter/rules          — liste
-- GET/POST /admin/config/filter/rules/new  — nouvelle règle
-- GET/POST /admin/config/filter/rules/:n/edit
-- POST     /admin/config/filter/rules/:n/delete
-- POST     /admin/config/filter/rules/:n/move

H        = require "auth.html"
{ :css }  = require "webui.css"
{ :page } = require "webui.handlers.dashboard"
{ :read_config, :write_config } = require "webui.serializer"
registry = require "webui.schema.registry"

parse_form = (body) ->
  return {} unless body
  out = {}
  dec = (s) -> (s\gsub "%%(%x%x)", (h) -> string.char tonumber h, 16)\gsub "+", " "
  for k, v in body\gmatch "([^&=]+)=([^&]*)"
    out[dec k] = dec v
  out

-- ── Résumé d'une règle pour la liste ──────────────────────────────────────

rule_summary = (rule) ->
  desc  = rule.description or "(sans titre)"
  conds_parts = {}
  if rule.conditions
    for k, v in pairs rule.conditions
      val_str = if type(v) == "table"
        "[" .. table.concat([tostring i for i in *v], ", ") .. "]"
      else
        tostring v
      conds_parts[#conds_parts + 1] = "#{k}: #{val_str}"
  acts_parts = {}
  if rule.actions
    for _, a in ipairs rule.actions
      acts_parts[#acts_parts + 1] = if type(a) == "table"
        next_k = nil
        for k in pairs a
          next_k = k
          break
        next_k or "?"
      else
        tostring a
  desc, table.concat(conds_parts, " AND "), table.concat(acts_parts, ", ")

-- ── Liste des règles ─────────────────────────────────────────────────────

handle_rules_list = (req, state) ->
  cfg, err = read_config state.config_path
  return 500, {}, "Erreur config : #{err}" unless cfg
  rules = (cfg.filter or {}).rules or {}

  rows = ""
  for i, rule in ipairs rules
    desc, conds_str, acts_str = rule_summary rule
    cond_cell = if conds_str ~= "" then conds_str else H.em "(toujours)"
    btn_move = H.form { method: "POST", action: "/admin/config/filter/rules/#{i}/move", style: "display:inline" },
      H.button({ type: "submit", name: "dir", value: "up",   class: "btn btn-secondary btn-sm" }, "↑") ..
      H.button({ type: "submit", name: "dir", value: "down", class: "btn btn-secondary btn-sm" }, "↓")
    btn_del  = H.form { method: "POST", action: "/admin/config/filter/rules/#{i}/delete", style: "display:inline" },
      H.button { type: "submit", class: "btn btn-danger btn-sm",
                 onclick: "return confirm('Supprimer ?')" }, "✕"
    btn_edit = H.a { class: "btn btn-secondary btn-sm", href: "/admin/config/filter/rules/#{i}/edit" }, "Éditer"
    rows ..= H.tr {
      H.td tostring(i)
      H.td desc
      H.td { class: "mono" }, cond_cell
      H.td { class: "mono" }, acts_str
      H.td { class: "actions" }, btn_edit .. " " .. btn_move .. " " .. btn_del
    }

  thead = H.thead {
    H.tr {
      H.th { style: "width:2.5rem" }, "#"
      H.th { style: "width:20%" }, "Description"
      H.th "Conditions"
      H.th { style: "width:12%" }, "Action"
      H.th { style: "width:11rem" }, ""
    }
  }
  tbl = H.table (thead .. H.tbody rows)

  body = H.section {
    H.h2 "Règles de filtrage"
    H.p { H.a { class: "btn", href: "/admin/config/filter/rules/new" }, "Ajouter une règle" }
    tbl
  }
  200, { ["Content-Type"]: "text/html; charset=UTF-8" }, page "Règles de filtrage", body

-- ── Formulaire de règle autogénéré ─────────────────────────────────────────

-- Options triées catégorie + label pour le select de type de condition
cond_type_opts = (selected_type) ->
  conds = registry.conditions!
  ordered = {}
  for name, s in pairs conds
    ordered[#ordered + 1] = {name, s}
  table.sort ordered, (a, b) ->
    ca = a[2].category or "z"
    cb = b[2].category or "z"
    if ca == cb then a[2].label < b[2].label else ca < cb
  opts = ""
  for _, pair in ipairs ordered
    name, s = pair[1], pair[2]
    sel = if name == selected_type then "selected" else nil
    opts ..= H.option { value: name, selected: sel }, (s.label or name)
  opts

cond_val_str = (cval) ->
  if type(cval) == "table" then table.concat(cval, "\n")
  elseif cval then tostring cval
  else ""

-- Une ligne du tableau de conditions (idx = entier ou "__I__" pour le template)
render_cond_row = (idx, ctype, cval) ->
  sel = H.select { name: "cond_#{idx}[type]" }, cond_type_opts(ctype)
  ta  = H.textarea { name: "cond_#{idx}[value]", rows: "2" }, cond_val_str(cval)
  btn = H.button { type: "button", onclick: "_delCond(this)", class: "btn btn-danger btn-sm" }, "✕"
  H.tr (H.td(sel) .. H.td(ta) .. H.td(btn))

-- Ancienne signature gardée pour compatibilité interne (non utilisée en dehors)
render_condition_input = (prefix, cond_name, schema, current_val) ->
  t = schema and schema.arg_type
  return "" unless t
  fname = prefix .. "[value]"
  hint = schema.arg_hint or ""

  if t == "string" or t == "string_or_table"
    val = if type(current_val) == "string" then current_val else ""
    return H.div {
      H.label (schema.label or cond_name) .. " — valeur"
      H.input { type: "text", name: fname, value: val, placeholder: hint }
    }
  elseif t == "integer"
    val = if type(current_val) == "number" then tostring current_val else ""
    return H.div {
      H.label (schema.label or cond_name)
      H.input { type: "number", name: fname, value: val, placeholder: hint }
    }
  elseif t == "string_list"
    val = if type(current_val) == "table"
      table.concat current_val, "\n"
    elseif type(current_val) == "string" then current_val
    else ""
    return H.div {
      H.label (schema.label or cond_name) .. " (une valeur par ligne)"
      H.textarea { name: fname, rows: "3" }, val
    }
  elseif t == "condition_list" or t == "condition"
    return H.div {
      H.p { style: "color:#888;font-style:italic" }, "Édition manuelle requise pour les méta-conditions."
      H.input { type: "text", name: fname, value: "" }
    }
  ""

render_condition_select = (prefix, current_type, current_val) ->
  conds = registry.conditions!
  -- Trier par catégorie puis par label
  ordered = {}
  for name, s in pairs conds
    ordered[#ordered + 1] = {name, s}
  table.sort ordered, (a, b) ->
    ca = a[2].category or "z"
    cb = b[2].category or "z"
    if ca == cb then a[2].label < b[2].label else ca < cb

  opts = ""
  for _, pair in ipairs ordered
    name, s = pair[1], pair[2]
    sel = if name == current_type then "selected" else nil
    opts ..= H.option { value: name, selected: sel }, (s.label or name)

  sel_id = prefix .. "_type"
  -- Fieldsets pour chaque type (hidden, revealed by JS)
  fieldsets = ""
  for _, pair in ipairs ordered
    name, s = pair[1], pair[2]
    fid = prefix .. "_fields_" .. name\gsub("[^%w]","_")
    display = if name == current_type then "" else "display:none"
    field_input = render_condition_input prefix, name, s, current_val
    fieldsets ..= H.div { id: fid, style: display }, field_input

  -- JS minimal pour show/hide
  js = [[
    document.getElementById(']] .. sel_id .. [[').addEventListener('change', function() {
      var val = this.value;
      var prefix = ']] .. prefix .. [[';
      document.querySelectorAll('[id^="' + prefix + '_fields_"]').forEach(function(el) {
        el.style.display = 'none';
      });
      var target = document.getElementById(prefix + '_fields_' + val.replace(/[^a-zA-Z0-9]/g, '_'));
      if (target) target.style.display = '';
    });
  ]]

  H.div {
    H.label "Type de condition"
    H.select { id: sel_id, name: prefix .. "[type]" }, opts
    fieldsets
    H.script js
  }

render_action_select = (prefix, current_type, current_opts) ->
  acts = registry.actions!
  opts = ""
  for name, s in pairs acts
    sel = if name == current_type then "selected" else nil
    opts ..= H.option { value: name, selected: sel }, (s and s.label or name)

  -- Option pour les actions avec paramètres
  extra = ""
  if current_type == "dns_strip"
    rr_val = if type(current_opts) == "table" then current_opts.rr_type or "A" else "A"
    extra = H.div {
      H.label "Type d'enregistrement à supprimer"
      H.select { name: prefix .. "[rr_type]" },
        H.option { value: "A",     selected: rr_val == "A"     and "selected" or nil }, "A (IPv4)"
        H.option { value: "AAAA",  selected: rr_val == "AAAA"  and "selected" or nil }, "AAAA (IPv6)"
        H.option { value: "CNAME", selected: rr_val == "CNAME" and "selected" or nil }, "CNAME"
        H.option { value: "MX",    selected: rr_val == "MX"    and "selected" or nil }, "MX"
    }
  elseif current_type == "log"
    msg_val = if type(current_opts) == "table" then current_opts.log_msg or "" else ""
    extra = H.div {
      H.label "Message de log (optionnel)"
      H.input { type: "text", name: prefix .. "[log_msg]", value: msg_val }
    }

  H.div {
    H.label "Action"
    H.select { name: prefix .. "[type]" }, opts
    extra
  }

-- Génère le formulaire complet d'une règle (conditions dynamiques)
render_rule_form = (action_url, rule) ->
  rule or= {}
  conds   = rule.conditions or {}
  actions = rule.actions or {}

  -- Description
  desc_html = H.div {
    H.label "Description"
    H.input { type: "text", name: "description", value: rule.description or "" }
  }

  -- Tableau de conditions existantes
  cond_rows = ""
  idx = 0
  for ctype, cval in pairs conds
    cond_rows ..= render_cond_row idx, ctype, cval
    idx += 1

  -- Ligne-template pour JS (dans <template>, non soumise)
  tpl_sel = H.select { name: "cond___I__[type]" }, cond_type_opts(nil)
  tpl_ta  = H.textarea { name: "cond___I__[value]", rows: "2" }, ""
  tpl_btn = H.button { type: "button", onclick: "_delCond(this)", class: "btn btn-danger btn-sm" }, "✕"
  tpl_row = H.tr (H.td(tpl_sel) .. H.td(tpl_ta) .. H.td(tpl_btn))
  cond_tpl = H.template { id: "cond-tpl" }, tpl_row

  cond_thead = H.thead {
    H.tr {
      H.th "Type de condition"
      H.th "Valeur (une par ligne pour les listes)"
      H.th { style: "width:3rem" }, ""
    }
  }
  cond_tbody = H.tbody { id: "cond-body" }, cond_rows
  cond_table = H.table (cond_thead .. cond_tbody)
  add_btn = H.button { type: "button", onclick: "_addCond()", class: "btn btn-secondary btn-sm",
                       style: "margin:.4rem 0 .75rem" }, "+ Ajouter une condition"
  js = "var _ci=#{idx};function _addCond(){" ..
    "var t=document.getElementById('cond-tpl').content.cloneNode(true).querySelector('tr');" ..
    "t.querySelectorAll('[name]').forEach(function(e){e.name=e.name.replace('__I__',_ci);});" ..
    "_ci++;document.getElementById('cond-body').appendChild(t);}" ..
    "function _delCond(b){b.closest('tr').remove();}"

  -- Action
  action_type = nil
  action_opts = nil
  if #actions > 0
    first = actions[1]
    if type(first) == "string"
      action_type = first
    elseif type(first) == "table"
      for k in pairs first
        action_type = k
        action_opts = first[k]
        break

  action_html = H.fieldset {
    H.legend "Action"
    render_action_select "action", action_type, action_opts
  }

  buttons = H.div { style: "margin-top:1rem" },
    H.button({ type: "submit" }, "Enregistrer") ..
    " " ..
    H.a({ class: "btn btn-secondary", href: "/admin/config/filter/rules" }, "Annuler")

  body_html = desc_html ..
    H.h3("Conditions — toutes en AND") ..
    cond_tpl .. cond_table .. add_btn ..
    H.h3("Action") ..
    action_html .. buttons ..
    H.script(js)

  H.form { method: "POST", action: action_url }, body_html

-- Reconstruit une règle depuis le formulaire POST
-- Les indices sont épars (suppression possible côté client), on scanne 0..49
rebuild_rule = (form) ->
  rule = {}
  rule.description = form.description or ""

  conditions = {}
  conds_reg = registry.conditions!
  for i = 0, 49
    ctype = form["cond_#{i}[type]"]
    cval  = form["cond_#{i}[value]"] or ""
    continue unless ctype and ctype ~= ""
    continue unless cval\match "%S"
    s = conds_reg[ctype]
    if s and s.arg_type == "string_list"
      items = {}
      for line in cval\gmatch "[^\n]+"
        line = line\match "^%s*(.-)%s*$"
        items[#items + 1] = line unless line == ""
      conditions[ctype] = items if #items > 0
    elseif s and s.arg_type == "integer"
      conditions[ctype] = tonumber cval
    else
      conditions[ctype] = cval\match "^%s*(.-)%s*$"

  rule.conditions = conditions if next conditions

  atype = form["action[type]"]
  if atype and atype ~= ""
    if atype == "dns_strip"
      rule.actions = { { dns_strip: { rr_type: form["action[rr_type]"] or "A" } } }
    elseif atype == "log"
      rule.actions = { { log: { log_msg: form["action[log_msg]"] or "" } } }
    else
      rule.actions = { atype }

  rule

-- ── Handlers ─────────────────────────────────────────────────────────────

handle_rules_new_get = (req, state) ->
  body = H.section {
    H.h2 "Nouvelle règle"
    render_rule_form "/admin/config/filter/rules/new", nil
  }
  200, { ["Content-Type"]: "text/html; charset=UTF-8" }, page "Nouvelle règle", body

handle_rules_new_post = (req, state) ->
  form = parse_form req.body
  cfg, err = read_config state.config_path
  return 500, {}, "Erreur config : #{err}" unless cfg
  cfg.filter or= {}
  cfg.filter.rules or= {}
  rule = rebuild_rule form
  cfg.filter.rules[#cfg.filter.rules + 1] = rule
  ok, e = write_config cfg, state.config_path
  return 500, {}, "Erreur écriture : #{e}" unless ok
  302, { ["Location"]: "/admin/config/filter/rules" }, ""

handle_rules_edit_get = (req, n, state) ->
  cfg, err = read_config state.config_path
  return 500, {}, "Erreur config : #{err}" unless cfg
  rules = (cfg.filter or {}).rules or {}
  rule  = rules[n]
  return 404, {}, "Règle #{n} introuvable" unless rule
  body = H.section {
    H.h2 "Éditer la règle #{n}"
    render_rule_form "/admin/config/filter/rules/#{n}/edit", rule
  }
  200, { ["Content-Type"]: "text/html; charset=UTF-8" }, page "Éditer règle #{n}", body

handle_rules_edit_post = (req, n, state) ->
  form = parse_form req.body
  cfg, err = read_config state.config_path
  return 500, {}, "Erreur config : #{err}" unless cfg
  rules = (cfg.filter or {}).rules or {}
  return 404, {}, "Règle #{n} introuvable" unless rules[n]
  rules[n] = rebuild_rule form
  cfg.filter.rules = rules
  ok, e = write_config cfg, state.config_path
  return 500, {}, "Erreur écriture : #{e}" unless ok
  302, { ["Location"]: "/admin/config/filter/rules" }, ""

handle_rules_delete = (req, n, state) ->
  cfg, err = read_config state.config_path
  return 500, {}, "Erreur config : #{err}" unless cfg
  rules = (cfg.filter or {}).rules or {}
  return 404, {}, "Règle #{n} introuvable" unless rules[n]
  table.remove rules, n
  cfg.filter.rules = rules
  ok, e = write_config cfg, state.config_path
  return 500, {}, "Erreur écriture : #{e}" unless ok
  302, { ["Location"]: "/admin/config/filter/rules" }, ""

handle_rules_move = (req, n, state) ->
  form = parse_form req.body
  dir = form.dir
  cfg, err = read_config state.config_path
  return 500, {}, "Erreur config : #{err}" unless cfg
  rules = (cfg.filter or {}).rules or {}
  return 404, {}, "Règle #{n} introuvable" unless rules[n]
  other = if dir == "up" then n - 1 else n + 1
  if rules[other]
    rules[n], rules[other] = rules[other], rules[n]
    cfg.filter.rules = rules
    ok, e = write_config cfg, state.config_path
    return 500, {}, "Erreur écriture : #{e}" unless ok
  302, { ["Location"]: "/admin/config/filter/rules" }, ""

{
  :handle_rules_list
  :handle_rules_new_get,   :handle_rules_new_post
  :handle_rules_edit_get,  :handle_rules_edit_post
  :handle_rules_delete,    :handle_rules_move
}
