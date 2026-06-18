local H = require("auth.html")
local page
page = require("webui.handlers.dashboard").page
local read_config, write_config
do
  local _obj_0 = require("webui.serializer")
  read_config, write_config = _obj_0.read_config, _obj_0.write_config
end
local config_schema = require("webui.schema.config_schema")
local unpack = unpack or table.unpack
local render_field
render_field = function(name, field_schema, current_val)
  local t = field_schema.type
  local label = field_schema.label or name
  local hint = field_schema.hint
  local val = current_val
  if val == nil then
    val = field_schema.default
  end
  local label_html = H.label(label)
  local hint_html
  if hint then
    hint_html = H.small({
      style = "color:#888"
    }, " (" .. tostring(hint) .. ")")
  else
    hint_html = ""
  end
  if t == "boolean" then
    local checked
    if val then
      checked = "checked"
    else
      checked = nil
    end
    local input = H.input({
      type = "checkbox",
      name = name,
      value = "1",
      checked = checked
    })
    return H.div({
      label_html .. " " .. input,
      H.input({
        type = "hidden",
        name = name .. "_present",
        value = "1"
      })
    })
  elseif t == "enum" then
    local opts = ""
    local _list_0 = (field_schema.values or { })
    for _index_0 = 1, #_list_0 do
      local v = _list_0[_index_0]
      local sel
      if v == tostring(val) then
        sel = "selected"
      else
        sel = nil
      end
      opts = opts .. H.option({
        value = v,
        selected = sel
      }, v)
    end
    return H.div({
      label_html .. hint_html,
      H.select({
        name = name
      }, opts)
    })
  elseif t == "integer" then
    return H.div({
      label_html .. hint_html,
      H.input({
        type = "number",
        name = name,
        value = tostring(val or ""),
        step = "1"
      })
    })
  elseif t == "path" or t == "string" then
    return H.div({
      label_html .. hint_html,
      H.input({
        type = "text",
        name = name,
        value = tostring(val or "")
      })
    })
  elseif t == "string_list" then
    local list_val
    if type(val) == "table" then
      list_val = table.concat(val, "\n")
    else
      list_val = tostring(val or "")
    end
    return H.div({
      label_html .. H.small({
        style = "color:#888"
      }, " (une valeur par ligne)"),
      H.textarea({
        name = name
      }, list_val)
    })
  else
    return H.div({
      label_html,
      H.p({
        style = "color:#888; font-style:italic"
      }, "Éditable dans la section dédiée.")
    })
  end
end
local render_subsection
render_subsection = function(sub_name, sub_schema, current_vals)
  local sub_label = sub_schema._label or sub_name
  local fields_html = ""
  for k, v in pairs(sub_schema) do
    local _continue_0 = false
    repeat
      if k:match("^_") then
        _continue_0 = true
        break
      end
      if not (type(v) == "table" and v.type) then
        _continue_0 = true
        break
      end
      local cur = current_vals and current_vals[k]
      fields_html = fields_html .. render_field(tostring(sub_name) .. "[" .. tostring(k) .. "]", v, cur)
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  return H.fieldset({
    H.legend(sub_label),
    fields_html
  })
end
local parse_form
parse_form = function(body)
  if not (body) then
    return { }
  end
  local out = { }
  local dec
  dec = function(s)
    return (s:gsub("%%(%x%x)", function(h)
      return string.char(tonumber(h, 16))
    end)):gsub("+", " ")
  end
  for k, v in body:gmatch("([^&=]+)=([^&]*)") do
    out[dec(k)] = dec(v)
  end
  return out
end
local build_section
build_section = function(schema, prefix, form_data)
  local result = { }
  for k, field in pairs(schema) do
    local _continue_0 = false
    repeat
      if k:match("^_") then
        _continue_0 = true
        break
      end
      local key
      if prefix then
        key = tostring(prefix) .. "[" .. tostring(k) .. "]"
      else
        key = k
      end
      if type(field) == "table" and field._label then
        local sub = build_section(field, k, form_data)
        if next(sub) then
          result[k] = sub
        end
      elseif type(field) == "table" and field.type then
        local raw = form_data[key]
        local t = field.type
        if t == "boolean" then
          result[k] = form_data[key] == "1"
        elseif t == "integer" then
          result[k] = tonumber(raw) or field.default
        elseif t == "string_list" then
          local items = { }
          for line in (raw or ""):gmatch("[^\n]+") do
            line = line:match("^%s*(.-)%s*$")
            if not (line == "") then
              items[#items + 1] = line
            end
          end
          result[k] = items
        else
          result[k] = raw or field.default or ""
        end
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  return result
end
local EDITABLE_SECTIONS = {
  "runtime",
  "nfqueue",
  "dns",
  "nft",
  "ipc",
  "clients",
  "mac_learner",
  "auth",
  "doh",
  "events",
  "metrics",
  "rtp"
}
local render_section_fields
render_section_fields = function(section, section_schema, current)
  local fields_html = ""
  for k, v in pairs(section_schema) do
    local _continue_0 = false
    repeat
      if k:match("^_") then
        _continue_0 = true
        break
      end
      if type(v) == "table" and v._label then
        fields_html = fields_html .. render_subsection(k, v, current[k])
      elseif type(v) == "table" and v.type then
        fields_html = fields_html .. render_field(k, v, current[k])
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  return fields_html
end
local render_section_details
render_section_details = function(section, section_schema, current)
  local label = section_schema._label or section
  local desc = section_schema._description or ""
  local fields_html = render_section_fields(section, section_schema, current)
  local desc_html
  if desc ~= "" then
    desc_html = H.p({
      style = "color:#555; margin-bottom:.5rem"
    }, desc)
  else
    desc_html = ""
  end
  local save_btn = H.div({
    style = "margin-top:.75rem"
  }, H.button({
    type = "submit"
  }, "Enregistrer"))
  local form_inner = desc_html .. fields_html .. save_btn
  local form_html = H.form({
    method = "POST",
    action = "/admin/config/" .. tostring(section)
  }, form_inner)
  local summary = H.summary(label)
  return H.details({
    id = "section-" .. tostring(section)
  }, summary .. form_html)
end
local is_filter_scalar
is_filter_scalar = function(field)
  if not (type(field) == "table" and field.type) then
    return false
  end
  return field.type ~= "named_map" and field.type ~= "rules_list"
end
local render_filter_general_details
render_filter_general_details = function(filter_schema, current)
  local fields_html = ""
  for k, field in pairs(filter_schema) do
    local _continue_0 = false
    repeat
      if k:match("^_") then
        _continue_0 = true
        break
      end
      if not (is_filter_scalar(field)) then
        _continue_0 = true
        break
      end
      fields_html = fields_html .. render_field(k, field, current[k])
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  local save_btn = H.div({
    style = "margin-top:.75rem"
  }, H.button({
    type = "submit"
  }, "Enregistrer"))
  local form_html = H.form({
    method = "POST",
    action = "/admin/config/filter/general"
  }, fields_html .. save_btn)
  local summary = H.summary("Filtre — Général (SafeSearch, YouTube, listes, domaines autorisés…)")
  return H.details({
    id = "section-filter-general"
  }, summary .. form_html)
end
local handle_config_index
handle_config_index = function(req, state)
  local cfg, err = read_config(state.config_path)
  if not (cfg) then
    return 500, { }, "Erreur config : " .. tostring(err)
  end
  local sections_html = ""
  for _index_0 = 1, #EDITABLE_SECTIONS do
    local _continue_0 = false
    repeat
      local s = EDITABLE_SECTIONS[_index_0]
      local schema = config_schema[s]
      if not (schema) then
        _continue_0 = true
        break
      end
      sections_html = sections_html .. render_section_details(s, schema, cfg[s] or { })
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  local filter_general = render_filter_general_details(config_schema.filter, cfg.filter or { })
  local filter_links = H.section({
    H.h2("Filtre DNS — éditeurs dédiés"),
    H.p({
      style = "color:#555"
    }, "Outils avec leurs propres formulaires (ajout, suppression, réordonnancement)."),
    H.ul({
      H.li({
        H.a({
          href = "/admin/config/filter/rules"
        }, "Règles de filtrage")
      }),
      H.li({
        H.a({
          href = "/admin/config/filter/lists"
        }, "Listes")
      }),
      H.li({
        H.a({
          href = "/admin/config/filter/decision"
        }, "Politique de décision")
      }),
      H.li({
        H.a({
          href = "/admin/config/filter/nets"
        }, "Réseaux nommés")
      }),
      H.li({
        H.a({
          href = "/admin/config/filter/macs"
        }, "MACs nommées")
      }),
      H.li({
        H.a({
          href = "/admin/config/devices"
        }, "Appareils vus / enregistrement MAC")
      }),
      H.li({
        H.a({
          href = "/admin/config/filter/users"
        }, "Utilisateurs")
      }),
      H.li({
        H.a({
          href = "/admin/config/filter/times"
        }, "Plages horaires")
      })
    })
  })
  local js = "if(location.hash){var d=document.querySelector(location.hash);if(d&&d.tagName==='DETAILS')d.open=true;}"
  local body_html = H.h2("Configuration") .. filter_general .. sections_html .. filter_links .. H.script(js)
  return 200, {
    ["Content-Type"] = "text/html; charset=UTF-8"
  }, page("Configuration", body_html)
end
local handle_config_section_get
handle_config_section_get = function(req, section, state)
  local section_schema = config_schema[section]
  if not (section_schema) then
    return 404, { }, "Section inconnue : " .. tostring(section)
  end
  local cfg, err = read_config(state.config_path)
  if not (cfg) then
    return 500, { }, "Erreur lecture config : " .. tostring(tostring(err))
  end
  local label = section_schema._label or section
  local desc = section_schema._description or ""
  local fields = render_section_fields(section, section_schema, cfg[section] or { })
  local desc_html
  if desc ~= "" then
    desc_html = H.p({
      style = "color:#555"
    }, desc)
  else
    desc_html = ""
  end
  local save_btn = H.div({
    style = "margin-top:.75rem"
  }, H.button({
    type = "submit"
  }, "Enregistrer") .. " " .. H.a({
    class = "btn btn-secondary",
    href = "/admin/config/"
  }, "Annuler"))
  local form_inner = desc_html .. fields .. save_btn
  local body = H.section({
    H.h2(label) .. H.form({
      method = "POST",
      action = "/admin/config/" .. tostring(section)
    }, form_inner)
  })
  return 200, {
    ["Content-Type"] = "text/html; charset=UTF-8"
  }, page(label, body)
end
local handle_config_section_post
handle_config_section_post = function(req, section, state)
  local section_schema = config_schema[section]
  if not (section_schema) then
    return 404, { }, "Section inconnue : " .. tostring(section)
  end
  local form = parse_form(req.body)
  local cfg, err = read_config(state.config_path)
  if not (cfg) then
    return 500, { }, "Erreur lecture config : " .. tostring(tostring(err))
  end
  cfg[section] = build_section(section_schema, nil, form)
  local ok2, err2 = write_config(cfg, state.config_path)
  if not (ok2) then
    return 500, { }, "Erreur écriture config : " .. tostring(tostring(err2))
  end
  return 302, {
    ["Location"] = "/admin/config/#section-" .. tostring(section)
  }, ""
end
local handle_filter_general_get
handle_filter_general_get = function(req, state)
  local cfg, err = read_config(state.config_path)
  if not (cfg) then
    return 500, { }, "Erreur config : " .. tostring(err)
  end
  local fschema = config_schema.filter
  local current = cfg.filter or { }
  local fields = ""
  for k, field in pairs(fschema) do
    local _continue_0 = false
    repeat
      if k:match("^_") then
        _continue_0 = true
        break
      end
      if not (is_filter_scalar(field)) then
        _continue_0 = true
        break
      end
      fields = fields .. render_field(k, field, current[k])
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  local save_btn = H.div({
    style = "margin-top:.75rem"
  }, H.button({
    type = "submit"
  }, "Enregistrer") .. " " .. H.a({
    class = "btn btn-secondary",
    href = "/admin/config/"
  }, "Annuler"))
  local body = H.section({
    H.h2("Filtre — Général") .. H.form({
      method = "POST",
      action = "/admin/config/filter/general"
    }, fields .. save_btn)
  })
  return 200, {
    ["Content-Type"] = "text/html; charset=UTF-8"
  }, page("Filtre — Général", body)
end
local handle_filter_general_post
handle_filter_general_post = function(req, state)
  local form = parse_form(req.body)
  local cfg, err = read_config(state.config_path)
  if not (cfg) then
    return 500, { }, "Erreur lecture config : " .. tostring(tostring(err))
  end
  cfg.filter = cfg.filter or { }
  local fschema = config_schema.filter
  for k, field in pairs(fschema) do
    local _continue_0 = false
    repeat
      if k:match("^_") then
        _continue_0 = true
        break
      end
      if not (is_filter_scalar(field)) then
        _continue_0 = true
        break
      end
      local t = field.type
      if t == "boolean" then
        cfg.filter[k] = form[k] == "1"
      elseif t == "integer" then
        cfg.filter[k] = tonumber(form[k]) or field.default
      elseif t == "string_list" then
        local items = { }
        for line in (form[k] or ""):gmatch("[^\n]+") do
          line = line:match("^%s*(.-)%s*$")
          if not (line == "") then
            items[#items + 1] = line
          end
        end
        cfg.filter[k] = items
      else
        cfg.filter[k] = form[k] or field.default or ""
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  local ok2, err2 = write_config(cfg, state.config_path)
  if not (ok2) then
    return 500, { }, "Erreur écriture config : " .. tostring(tostring(err2))
  end
  return 302, {
    ["Location"] = "/admin/config/#section-filter-general"
  }, ""
end
return {
  handle_config_index = handle_config_index,
  handle_config_section_get = handle_config_section_get,
  handle_config_section_post = handle_config_section_post,
  handle_filter_general_get = handle_filter_general_get,
  handle_filter_general_post = handle_filter_general_post
}
