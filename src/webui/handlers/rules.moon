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
    btn_move = H.form { method: "POST", action: "/admin/config/filter/rules/#{i}/move", style: "display:inline" }, {
      H.button({ type: "submit", name: "dir", value: "up",   class: "btn btn-secondary btn-sm" }, "↑") ..
      H.button({ type: "submit", name: "dir", value: "down", class: "btn btn-secondary btn-sm" }, "↓")
    }
    btn_del  = H.form { method: "POST", action: "/admin/config/filter/rules/#{i}/delete", style: "display:inline" }, {
      H.button { type: "submit", class: "btn btn-danger btn-sm",
                 onclick: "return confirm('Supprimer ?')" }, "✕"
    }
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

cond_val_str = (cval) ->
  if type(cval) == "table" then table.concat(cval, "\n")
  elseif cval then tostring cval
  else ""

-- Suffixe réel d'une forme de variante (clé UI → suffixe de nom de condition)
FORM_SUFFIX = { base: "", plural: "s", list: "_list", lists: "_lists" }

-- Recherche une famille par sa racine dans la liste ordonnée
fam_by_root = (families, root) ->
  for f in *families
    return f if f.root == root
  families[1]

-- Dropdown A — type de condition, groupé par catégorie (optgroups)
cond_a_select = (families, idx, sel_root) ->
  parts = {}
  cur_cat = nil
  for f in *families
    if f.category != cur_cat
      parts[#parts + 1] = "</optgroup>" if cur_cat != nil
      parts[#parts + 1] = "<optgroup label=\"#{registry.category_label f.category}\">"
      cur_cat = f.category
    sel = if f.root == sel_root then "selected" else nil
    parts[#parts + 1] = H.option { value: f.root, selected: sel, title: (f.description or "") }, f.label
  parts[#parts + 1] = "</optgroup>" if cur_cat != nil
  H.select { class: "cond-a", name: "cond_#{idx}[base]", onchange: "_famChange(this)" }, table.concat parts

-- Dropdown B — forme de valeur (masqué si une seule forme dispo)
cond_b_select = (fam, idx, sel_form) ->
  parts = {}
  for fm in *fam.forms
    sel = if fm.key == sel_form then "selected" else nil
    parts[#parts + 1] = H.option { value: fm.key, selected: sel, title: (fm.description or "") }, fm.label
  hidden = #fam.forms <= 1
  H.select {
    class: "cond-b", name: "cond_#{idx}[form]", onchange: "_formChange(this)"
    style: hidden and "display:none" or nil
  }, table.concat parts

-- Une ligne du tableau de conditions (idx = entier ou "__I__" pour le template)
render_cond_row = (families, idx, root, form, value) ->
  root or= families[1].root
  fam = fam_by_root families, root
  form or= "base"
  a = cond_a_select families, idx, root
  b = cond_b_select fam, idx, form
  ta = H.textarea { class: "cond-value", name: "cond_#{idx}[value]", rows: "2" }, cond_val_str(value)
  help  = H.div { class: "cond-help",  style: "color:#555;font-size:.85em;margin-top:.2rem" }, ""
  links = H.div { class: "cond-links", style: "font-size:.85em;margin-top:.2rem" }, ""
  btn = H.button { type: "button", onclick: "_delCond(this)", class: "btn btn-danger btn-sm" }, "✕"
  H.tr (H.td(a .. b) .. H.td({ class: "cond-val" }, ta .. help .. links) .. H.td(btn))

-- Données des familles exposées au JS client (pour synchroniser A↔B)
jq = (s) ->
  s = tostring(s or "")
  s = s\gsub("\\", "\\\\")\gsub("\"", "\\\"")\gsub("\n", "\\n")\gsub("\r", "")
  "\"#{s}\""

cond_families_js = (families) ->
  fam_parts = {}
  for f in *families
    form_parts = {}
    for fm in *f.forms
      lt = fm.list_type and jq(fm.list_type) or "null"
      form_parts[#form_parts + 1] = "{k:#{jq fm.key},lbl:#{jq fm.label},hint:#{jq(fm.hint or '')},desc:#{jq(fm.description or '')},lt:#{lt}}"
    fam_parts[#fam_parts + 1] = "#{jq f.root}:{forms:[#{table.concat form_parts, ','}]}"
  "{#{table.concat fam_parts, ','}}"

-- Options <option> du type d'action (sélectionne current_type)
action_options = (acts, current_type) ->
  opts = ""
  for name, s in pairs acts
    sel = if name == current_type then "selected" else nil
    opts ..= H.option { value: name, selected: sel }, (s and s.label or name)
  opts

-- Une ligne du tableau d'actions (idx = entier ou "__I__" pour le template).
-- Les champs « paramètres » (dns_strip → rr_type, log → log_msg) sont tous
-- rendus mais masqués selon le type courant ; `_actChange` (JS) bascule leur
-- visibilité. rebuild_rule n'utilise que les champs du type sélectionné.
render_action_row = (acts, idx, atype, aopts) ->
  show    = (t) -> atype == t and nil or "display:none"
  rr_val  = (type(aopts) == "table" and aopts.rr_type)  or "A"
  msg_val = (type(aopts) == "table" and aopts.log_msg)  or ""
  type_sel = H.select { class: "act-type", name: "action_#{idx}[type]", onchange: "_actChange(this)" },
    action_options acts, atype
  dns_extra = H.div { class: "act-dns", style: show "dns_strip" }, {
    H.label "Type d'enregistrement à supprimer"
    H.select { name: "action_#{idx}[rr_type]" }, {
      H.option { value: "A",     selected: rr_val == "A"     and "selected" or nil }, "A (IPv4)"
      H.option { value: "AAAA",  selected: rr_val == "AAAA"  and "selected" or nil }, "AAAA (IPv6)"
      H.option { value: "CNAME", selected: rr_val == "CNAME" and "selected" or nil }, "CNAME"
      H.option { value: "MX",    selected: rr_val == "MX"    and "selected" or nil }, "MX"
    }
  }
  log_extra = H.div { class: "act-log", style: show "log" }, {
    H.label "Message de log (optionnel)"
    H.input { type: "text", name: "action_#{idx}[log_msg]", value: msg_val }
  }
  btn = H.button { type: "button", onclick: "_delAction(this)", class: "btn btn-danger btn-sm" }, "✕"
  H.tr (H.td(type_sel) .. H.td({ class: "act-params" }, dns_extra .. log_extra) .. H.td(btn))

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

  families = registry.condition_families!

  -- Tableau de conditions existantes : on résout (racine, forme) depuis le nom stocké
  cond_rows = ""
  idx = 0
  for ctype, cval in pairs conds
    root, form = registry.resolve_condition ctype
    cond_rows ..= render_cond_row families, idx, root, form, cval
    idx += 1

  -- Ligne-template pour JS (dans <template>, non soumise)
  tpl_row  = render_cond_row families, "__I__", nil, nil, nil
  cond_tpl = H.template { id: "cond-tpl" }, tpl_row

  cond_thead = H.thead {
    H.tr {
      H.th "Type de condition"
      H.th "Valeur"
      H.th { style: "width:3rem" }, ""
    }
  }
  cond_tbody = H.tbody { id: "cond-body" }, cond_rows
  cond_table = H.table (cond_thead .. cond_tbody)
  add_btn = H.button { type: "button", onclick: "_addCond()", class: "btn btn-secondary btn-sm",
                       style: "margin:.4rem 0 .75rem" }, "+ Ajouter une condition"
  js = "var _FAM=#{cond_families_js families};" ..
    "function _rebuildB(row){var a=row.querySelector('.cond-a'),b=row.querySelector('.cond-b');" ..
    "var fam=_FAM[a.value];if(!fam)return;b.innerHTML='';fam.forms.forEach(function(f){" ..
    "var o=document.createElement('option');o.value=f.k;o.textContent=f.lbl;if(f.desc)o.title=f.desc;b.appendChild(o);});" ..
    "b.style.display=fam.forms.length<=1?'none':'';}" ..
    "function _applyForm(row){var a=row.querySelector('.cond-a'),b=row.querySelector('.cond-b');" ..
    "var ta=row.querySelector('.cond-value'),help=row.querySelector('.cond-help');" ..
    "var fam=_FAM[a.value];if(!fam)return;var fk=b.value||'base',f=null;" ..
    "fam.forms.forEach(function(x){if(x.k===fk)f=x;});if(!f)f=fam.forms[0];if(!f)return;" ..
    "ta.placeholder=f.hint||'';help.textContent=f.desc||'';" ..
    "row._lt=(f.k==='list'||f.k==='lists')?f.lt:null;_renderLinks(row);}" ..
    "function _renderLinks(row){var links=row.querySelector('.cond-links');" ..
    "var ta=row.querySelector('.cond-value');links.innerHTML='';if(!row._lt)return;" ..
    "ta.value.split('\\n').forEach(function(line){var n=line.trim();if(!n)return;" ..
    "var a=document.createElement('a');a.href='/admin/config/filter/lists/'+" ..
    "encodeURIComponent(row._lt)+'/'+encodeURIComponent(n);a.target='_blank';a.rel='noopener';" ..
    "a.textContent='\\u270e '+n;a.style.marginRight='.6rem';links.appendChild(a);});}" ..
    "function _famChange(sel){var row=sel.closest('tr');_rebuildB(row);_applyForm(row);}" ..
    "function _formChange(sel){_applyForm(sel.closest('tr'));}" ..
    "var _ci=#{idx};function _addCond(){" ..
    "var t=document.getElementById('cond-tpl').content.cloneNode(true).querySelector('tr');" ..
    "t.querySelectorAll('[name]').forEach(function(e){e.name=e.name.replace('__I__',_ci);});" ..
    "_ci++;var body=document.getElementById('cond-body');body.appendChild(t);" ..
    "_applyForm(body.lastElementChild);}" ..
    "function _delCond(b){b.closest('tr').remove();}" ..
    "document.getElementById('cond-body').addEventListener('input',function(e){" ..
    "if(e.target.classList.contains('cond-value'))_renderLinks(e.target.closest('tr'));});" ..
    "Array.prototype.forEach.call(document.querySelectorAll('#cond-body tr'),_applyForm);"

  -- Actions (plusieurs possibles, appliquées dans l'ordre)
  acts_reg = registry.actions!
  -- Résout (type, opts) d'une action stockée (string nue ou { type: opts }).
  resolve_action = (a) ->
    if type(a) == "string"
      a, nil
    elseif type(a) == "table"
      for k, v in pairs a
        return k, v
      nil, nil
    else
      nil, nil

  action_rows = ""
  ai = 0
  for a in *actions
    at, ao = resolve_action a
    action_rows ..= render_action_row acts_reg, ai, at, ao
    ai += 1
  -- Au moins une ligne (règle neuve / sans action) : type par défaut.
  if ai == 0
    action_rows = render_action_row acts_reg, 0, nil, nil
    ai = 1

  act_tpl_row = render_action_row acts_reg, "__I__", nil, nil
  act_tpl     = H.template { id: "act-tpl" }, act_tpl_row
  act_thead   = H.thead {
    H.tr {
      H.th "Action"
      H.th "Paramètres"
      H.th { style: "width:3rem" }, ""
    }
  }
  act_tbody = H.tbody { id: "act-body" }, action_rows
  act_table = H.table (act_thead .. act_tbody)
  act_add_btn = H.button { type: "button", onclick: "_addAction()", class: "btn btn-secondary btn-sm",
                           style: "margin:.4rem 0 .75rem" }, "+ Ajouter une action"
  act_js = "function _actChange(sel){var row=sel.closest('tr');var t=sel.value;" ..
    "var d=row.querySelector('.act-dns'),l=row.querySelector('.act-log');" ..
    "if(d)d.style.display=(t==='dns_strip')?'':'none';" ..
    "if(l)l.style.display=(t==='log')?'':'none';}" ..
    "var _ai=#{ai};function _addAction(){" ..
    "var t=document.getElementById('act-tpl').content.cloneNode(true).querySelector('tr');" ..
    "t.querySelectorAll('[name]').forEach(function(e){e.name=e.name.replace('__I__',_ai);});" ..
    "_ai++;var body=document.getElementById('act-body');body.appendChild(t);" ..
    "_actChange(body.lastElementChild.querySelector('.act-type'));}" ..
    "function _delAction(b){var body=document.getElementById('act-body');" ..
    "if(body.rows.length>1)b.closest('tr').remove();}" ..
    "Array.prototype.forEach.call(document.querySelectorAll('#act-body .act-type'),_actChange);"

  buttons = H.div { style: "margin-top:1rem" }, {
    H.button({ type: "submit" }, "Enregistrer") ..
    " " ..
    H.a({ class: "btn btn-secondary", href: "/admin/config/filter/rules" }, "Annuler")
  }

  body_html = desc_html ..
    H.h3("Conditions — toutes en AND") ..
    cond_tpl .. cond_table .. add_btn ..
    H.h3("Actions — appliquées dans l'ordre") ..
    act_tpl .. act_table .. act_add_btn .. buttons ..
    H.script(js) ..
    H.script(act_js)

  H.form { method: "POST", action: action_url }, body_html

-- Reconstruit une règle depuis le formulaire POST
-- Les indices sont épars (suppression possible côté client), on scanne 0..49
rebuild_rule = (form) ->
  rule = {}
  rule.description = form.description or ""

  conditions = {}
  conds_reg = registry.conditions!
  for i = 0, 49
    base = form["cond_#{i}[base]"]
    fkey = form["cond_#{i}[form]"] or "base"
    cval = form["cond_#{i}[value]"] or ""
    continue unless base and base ~= ""
    continue unless cval\match "%S"
    ctype = base .. (FORM_SUFFIX[fkey] or "")
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

  -- Construit une action depuis un préfixe de champ (type + params éventuels).
  build_action = (prefix) ->
    atype = form["#{prefix}[type]"]
    return nil unless atype and atype ~= ""
    if atype == "dns_strip"
      { dns_strip: { rr_type: form["#{prefix}[rr_type]"] or "A" } }
    elseif atype == "log"
      { log: { log_msg: form["#{prefix}[log_msg]"] or "" } }
    else
      atype

  actions = {}
  -- Indices épars (suppression côté client), on scanne 0..49 comme les conditions.
  for i = 0, 49
    a = build_action "action_#{i}"
    actions[#actions + 1] = a if a
  -- Repli legacy : ancien formulaire mono-action (`action[type]`).
  if #actions == 0
    a = build_action "action"
    actions[#actions + 1] = a if a

  rule.actions = actions if #actions > 0

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
