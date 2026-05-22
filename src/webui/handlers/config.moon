-- src/webui/handlers/config.moon
-- GET  /admin/config/         — toutes les sections repliables
-- GET  /admin/config/:section — page dédiée (accès direct)
-- POST /admin/config/:section — sauvegarde, redirect → index#section

H       = require "auth.html"
{ :page } = require "webui.handlers.dashboard"
{ :read_config, :write_config } = require "webui.serializer"
config_schema = require "webui.schema.config_schema"
unpack or= table.unpack

-- ── Helpers formulaire ────────────────────────────────────────────────────

render_field = (name, field_schema, current_val) ->
  t     = field_schema.type
  label = field_schema.label or name
  hint  = field_schema.hint
  val   = current_val
  val   = field_schema.default if val == nil

  label_html = H.label label
  hint_html  = if hint then H.small { style: "color:#888" }, " (#{hint})" else ""

  if t == "boolean"
    checked = if val then "checked" else nil
    input = H.input { type: "checkbox", name: name, value: "1", checked: checked }
    return H.div {
      label_html .. " " .. input
      H.input { type: "hidden", name: name .. "_present", value: "1" }
    }
  elseif t == "enum"
    opts = ""
    for v in *(field_schema.values or {})
      sel = if v == tostring(val) then "selected" else nil
      opts ..= H.option { value: v, selected: sel }, v
    return H.div {
      label_html .. hint_html
      H.select { name: name }, opts
    }
  elseif t == "integer"
    return H.div {
      label_html .. hint_html
      H.input { type: "number", name: name, value: tostring(val or ""), step: "1" }
    }
  elseif t == "path" or t == "string"
    return H.div {
      label_html .. hint_html
      H.input { type: "text", name: name, value: tostring(val or "") }
    }
  elseif t == "string_list"
    list_val = if type(val) == "table" then table.concat(val, "\n") else tostring(val or "")
    return H.div {
      label_html .. H.small { style: "color:#888" }, " (une valeur par ligne)"
      H.textarea { name: name }, list_val
    }
  else
    return H.div {
      label_html
      H.p { style: "color:#888; font-style:italic" }, "Éditable dans la section dédiée."
    }

render_subsection = (sub_name, sub_schema, current_vals) ->
  sub_label  = sub_schema._label or sub_name
  fields_html = ""
  for k, v in pairs sub_schema
    continue if k\match "^_"
    continue unless type(v) == "table" and v.type
    cur = current_vals and current_vals[k]
    fields_html ..= render_field "#{sub_name}[#{k}]", v, cur
  H.fieldset {
    H.legend sub_label
    fields_html
  }

parse_form = (body) ->
  return {} unless body
  out = {}
  dec = (s) -> (s\gsub "%%(%x%x)", (h) -> string.char tonumber h, 16)\gsub "+", " "
  for k, v in body\gmatch "([^&=]+)=([^&]*)"
    out[dec k] = dec v
  out

build_section = (schema, prefix, form_data) ->
  result = {}
  for k, field in pairs schema
    continue if k\match "^_"
    key = if prefix then "#{prefix}[#{k}]" else k
    if type(field) == "table" and field._label
      sub = build_section field, k, form_data
      result[k] = sub if next sub
    elseif type(field) == "table" and field.type
      raw = form_data[key]
      t   = field.type
      if t == "boolean"
        result[k] = form_data[key] == "1"
      elseif t == "integer"
        result[k] = tonumber(raw) or field.default
      elseif t == "string_list"
        items = {}
        for line in (raw or "")\gmatch "[^\n]+"
          line = line\match "^%s*(.-)%s*$"
          items[#items + 1] = line unless line == ""
        result[k] = items
      else
        result[k] = raw or field.default or ""
  result

-- ── Sections disponibles ──────────────────────────────────────────────────

EDITABLE_SECTIONS = {
  "runtime", "nfqueue", "dns", "nft", "ipc", "clients",
  "mac_learner", "auth", "doh", "events", "metrics", "rtp"
}

-- ── Rendu d'une section comme <details> repliable ─────────────────────────

render_section_fields = (section, section_schema, current) ->
  fields_html = ""
  for k, v in pairs section_schema
    continue if k\match "^_"
    if type(v) == "table" and v._label
      fields_html ..= render_subsection k, v, current[k]
    elseif type(v) == "table" and v.type
      fields_html ..= render_field k, v, current[k]
  fields_html

render_section_details = (section, section_schema, current) ->
  label = section_schema._label or section
  desc  = section_schema._description or ""
  fields_html = render_section_fields section, section_schema, current
  desc_html   = if desc ~= "" then H.p { style: "color:#555; margin-bottom:.5rem" }, desc else ""
  save_btn    = H.div { style: "margin-top:.75rem" },
    H.button { type: "submit" }, "Enregistrer"
  form_inner  = desc_html .. fields_html .. save_btn
  form_html   = H.form { method: "POST", action: "/admin/config/#{section}" }, form_inner
  summary     = H.summary label
  H.details { id: "section-#{section}" }, summary .. form_html

-- ── Handlers ─────────────────────────────────────────────────────────────

handle_config_index = (req, state) ->
  cfg, err = read_config state.config_path
  return 500, {}, "Erreur config : #{err}" unless cfg

  sections_html = ""
  for s in *EDITABLE_SECTIONS
    schema = config_schema[s]
    continue unless schema
    sections_html ..= render_section_details s, schema, cfg[s] or {}

  filter_link = H.p {
    H.a { href: "/admin/config/filter" }, "Filtre DNS (règles, listes, décision)"
  }
  -- JS : ouvre le bon <details> si l'URL contient un fragment
  js = "if(location.hash){var d=document.querySelector(location.hash);if(d&&d.tagName==='DETAILS')d.open=true;}"

  body_html = H.h2("Configuration") .. filter_link .. sections_html .. H.script(js)
  200, { ["Content-Type"]: "text/html; charset=UTF-8" }, page "Configuration", body_html

handle_config_section_get = (req, section, state) ->
  section_schema = config_schema[section]
  return 404, {}, "Section inconnue : #{section}" unless section_schema

  cfg, err = read_config state.config_path
  return 500, {}, "Erreur lecture config : #{tostring err}" unless cfg

  label  = section_schema._label or section
  desc   = section_schema._description or ""
  fields = render_section_fields section, section_schema, cfg[section] or {}
  desc_html = if desc ~= "" then H.p { style: "color:#555" }, desc else ""
  save_btn  = H.div { style: "margin-top:.75rem" },
    H.button({ type: "submit" }, "Enregistrer") ..
    " " ..
    H.a({ class: "btn btn-secondary", href: "/admin/config/" }, "Annuler")
  form_inner = desc_html .. fields .. save_btn
  body = H.section { H.h2(label) .. H.form({ method: "POST", action: "/admin/config/#{section}" }, form_inner) }
  200, { ["Content-Type"]: "text/html; charset=UTF-8" }, page label, body

handle_config_section_post = (req, section, state) ->
  section_schema = config_schema[section]
  return 404, {}, "Section inconnue : #{section}" unless section_schema

  form = parse_form req.body
  cfg, err = read_config state.config_path
  return 500, {}, "Erreur lecture config : #{tostring err}" unless cfg

  cfg[section] = build_section section_schema, nil, form
  ok2, err2 = write_config cfg, state.config_path
  return 500, {}, "Erreur écriture config : #{tostring err2}" unless ok2

  302, { ["Location"]: "/admin/config/#section-#{section}" }, ""

{ :handle_config_index, :handle_config_section_get, :handle_config_section_post }
