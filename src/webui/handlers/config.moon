-- src/webui/handlers/config.moon
-- GET/POST /admin/config/:section — édition des sections scalaires.
-- Les formulaires sont autogénérés depuis config_schema.

H       = require "auth.html"
{ :css } = require "webui.css"
{ :page, :nav_html } = require "webui.handlers.dashboard"
{ :read_config, :write_config } = require "webui.serializer"
config_schema = require "webui.schema.config_schema"

-- ── Helpers formulaire ────────────────────────────────────────────────────

-- Génère un champ HTML depuis un descripteur de schéma et la valeur courante.
render_field = (name, field_schema, current_val) ->
  t = field_schema.type
  label = field_schema.label or name
  hint  = field_schema.hint
  val   = current_val
  val   = field_schema.default if val == nil

  label_html = H.label label
  hint_html  = if hint then H.small { style: "color:#888" }, " (#{hint})" else ""

  if t == "boolean"
    checked = if val then "checked" else nil
    input = H.input {
      type: "checkbox", name: name, value: "1"
      checked: checked
    }
    return H.div {
      label_html .. " " .. input
      H.input { type: "hidden", name: name .. "_present", value: "1" }
    }
  elseif t == "enum"
    select_inner = ""
    for v in *(field_schema.values or {})
      sel = if v == tostring(val) then "selected" else nil
      select_inner ..= H.option { value: v, selected: sel }, v
    return H.div {
      label_html .. hint_html
      H.select { name: name }, select_inner
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
    -- Une valeur par ligne dans un textarea
    list_val = if type(val) == "table" then table.concat(val, "\n") else tostring(val or "")
    return H.div {
      label_html .. H.small { style: "color:#888" }, " (une valeur par ligne)"
      H.textarea { name: name }, list_val
    }
  else
    -- Types complexes (named_map, rules_list, time_window) : lien vers page dédiée
    return H.div {
      label_html
      H.p { style: "color:#888; font-style:italic" }, "Éditable dans la section dédiée."
    }

-- Génère un fieldset pour une sous-section (section avec _label).
render_subsection = (sub_name, sub_schema, current_vals) ->
  sub_label = sub_schema._label or sub_name
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

-- Parse un body application/x-www-form-urlencoded.
parse_form = (body) ->
  return {} unless body
  out = {}
  dec = (s) -> (s\gsub "%%(%x%x)", (h) -> string.char tonumber h, 16)\gsub "+", " "
  for k, v in body\gmatch "([^&=]+)=([^&]*)"
    out[dec k] = dec v
  out

-- ── Sections disponibles ──────────────────────────────────────────────────

-- Sections éditables via ce handler (sections scalaires uniquement)
EDITABLE_SECTIONS = {
  "runtime", "nfqueue", "dns", "nft", "ipc", "clients",
  "mac_learner", "auth", "doh", "events", "metrics", "rtp"
}

-- ── Handlers ─────────────────────────────────────────────────────────────

handle_config_index = (req, state) ->
  links = {}
  for s in *EDITABLE_SECTIONS
    label_s = config_schema[s] and config_schema[s]._label or s
    links[#links + 1] = H.li { H.a { href: "/admin/config/#{s}" }, label_s }
  links[#links + 1] = H.li { H.a { href: "/admin/config/filter" }, "Filtre DNS (règles, listes)" }
  body = H.section {
    H.h2 "Sections de configuration"
    H.ul { table.unpack links }
  }
  200, { ["Content-Type"]: "text/html; charset=UTF-8" }, page "Configuration", body

handle_config_section_get = (req, section, state) ->
  section_schema = config_schema[section]
  unless section_schema
    return 404, {}, "Section inconnue : #{section}"

  -- Charger la config courante
  cfg, err = read_config state.config_path
  unless cfg
    return 500, {}, "Erreur lecture config : #{tostring err}"

  current = cfg[section] or {}
  label   = section_schema._label or section
  desc    = section_schema._description or ""

  fields_html = ""
  for k, v in pairs section_schema
    continue if k\match "^_"
    if type(v) == "table" and v._label
      -- Sous-section
      fields_html ..= render_subsection k, v, current[k]
    elseif type(v) == "table" and v.type
      -- Champ simple
      fields_html ..= render_field k, v, current[k]

  body = H.section {
    H.h2 label
    (if desc ~= "" then H.p { style: "color:#555" }, desc else "")
    H.form { method: "POST", action: "/admin/config/#{section}" },
      fields_html
      H.div { style: "margin-top:.75rem" },
        H.button { type: "submit" }, "Enregistrer"
        " "
        H.a { class: "btn btn-secondary", href: "/admin/config/" }, "Annuler"
  }
  200, { ["Content-Type"]: "text/html; charset=UTF-8" }, page label, body

handle_config_section_post = (req, section, state) ->
  section_schema = config_schema[section]
  unless section_schema
    return 404, {}, "Section inconnue : #{section}"

  form = parse_form req.body
  cfg, err = read_config state.config_path
  unless cfg
    return 500, {}, "Erreur lecture config : #{tostring err}"

  -- Reconstruire la section depuis le formulaire
  build_section = (schema, prefix, form_data) ->
    result = {}
    for k, field in pairs schema
      continue if k\match "^_"
      key = if prefix then "#{prefix}[#{k}]" else k
      if type(field) == "table" and field._label
        -- Sous-section récursive
        sub = build_section field, k, form_data
        result[k] = sub if next sub
      elseif type(field) == "table" and field.type
        raw = form_data[key]
        t = field.type
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

  cfg[section] = build_section section_schema, nil, form
  ok2, err2 = write_config cfg, state.config_path
  unless ok2
    return 500, {}, "Erreur écriture config : #{tostring err2}"

  -- PRG : redirect vers la page GET avec bandeau succès
  302, { ["Location"]: "/admin/config/#{section}?saved=1" }, ""

{ :handle_config_index, :handle_config_section_get, :handle_config_section_post }
