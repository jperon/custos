local H = require("auth.html")
local css
css = require("webui.css").css
local page
page = require("webui.handlers.dashboard").page
local read_config, write_config
do
  local _obj_0 = require("webui.serializer")
  read_config, write_config = _obj_0.read_config, _obj_0.write_config
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
local parse_form_multi
parse_form_multi = function(body)
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
    local dk = dec(k)
    local _update_0 = dk
    out[_update_0] = out[_update_0] or { }
    out[dk][#out[dk] + 1] = dec(v)
  end
  return out
end
local render_kv_editor
render_kv_editor = function(section_key, title, desc, value_label, current_map, value_hint)
  local rows = ""
  if current_map then
    for k, v in pairs(current_map) do
      local val_str
      if type(v) == "table" then
        val_str = table.concat(v, "\n")
      else
        val_str = tostring(v)
      end
      rows = rows .. H.tr({
        H.td({
          H.input({
            type = "text",
            name = "key[]",
            value = k,
            style = "margin:0"
          })
        }),
        H.td({
          H.textarea({
            name = "val[]",
            rows = "2",
            style = "margin:0; font-family:monospace"
          }, val_str)
        }),
        H.td({
          H.button({
            type = "submit",
            name = "delete",
            value = k,
            class = "btn btn-danger btn-sm"
          }, "✕")
        })
      })
    end
  end
  rows = rows .. H.tr({
    H.td({
      H.input({
        type = "text",
        name = "newkey",
        placeholder = "nouveau nom"
      })
    }),
    H.td({
      H.textarea({
        name = "newval",
        rows = "2",
        placeholder = value_hint or "valeur"
      }, "")
    }),
    H.td("")
  })
  return H.section({
    H.h2(title),
    H.p({
      style = "color:#555"
    }, desc),
    H.form({
      method = "POST",
      action = "/admin/config/filter/" .. tostring(section_key)
    }, {
      H.table({
        H.thead({
          H.tr({
            H.th("Nom", H.th(value_label, H.th("")))
          })
        }),
        H.tbody({ }, rows)
      }),
      H.div({
        style = "margin-top:.75rem"
      }, H.button({
        type = "submit",
        name = "action",
        value = "save"
      }, "Enregistrer"))
    }),
    " ",
    H.a({
      class = "btn btn-secondary",
      href = "/admin/config/"
    }, "Annuler")
  })
end
local render_times_editor
render_times_editor = function(current_times)
  local rows = ""
  if current_times then
    for k, v in pairs(current_times) do
      local start_s = type(v) == "table" and (v[1] or "") or ""
      local end_s = type(v) == "table" and (v[2] or "") or ""
      rows = rows .. H.tr({
        H.td({
          H.input({
            type = "text",
            name = "key[]",
            value = k
          })
        }),
        H.td({
          H.input({
            type = "time",
            name = "start[]",
            value = start_s
          })
        }),
        H.td({
          H.input({
            type = "time",
            name = "end[]",
            value = end_s
          })
        }),
        H.td({
          H.button({
            type = "submit",
            name = "delete",
            value = k,
            class = "btn btn-danger btn-sm"
          }, "✕")
        })
      })
    end
  end
  rows = rows .. H.tr({
    H.td({
      H.input({
        type = "text",
        name = "newkey",
        placeholder = "nom"
      })
    }),
    H.td({
      H.input({
        type = "time",
        name = "newstart",
        placeholder = "08:00"
      })
    }),
    H.td({
      H.input({
        type = "time",
        name = "newend",
        placeholder = "18:00"
      })
    }),
    H.td("")
  })
  return H.section({
    H.h2("Plages horaires"),
    H.p({
      style = "color:#555"
    }, "Définissez des fenêtres horaires réutilisables dans les règles."),
    H.form({
      method = "POST",
      action = "/admin/config/filter/times"
    }, {
      H.table({
        H.thead({
          H.tr({
            H.th("Nom", H.th("Début", H.th("Fin", H.th(""))))
          })
        }),
        H.tbody({ }, rows)
      }),
      H.div({
        style = "margin-top:.75rem"
      }, H.button({
        type = "submit",
        name = "action",
        value = "save"
      }, "Enregistrer"))
    }),
    " ",
    H.a({
      class = "btn btn-secondary",
      href = "/admin/config/"
    }, "Annuler")
  })
end
local make_get
make_get = function(section_key, title, desc, value_label, value_hint)
  return function(req, state)
    local cfg, err = read_config(state.config_path)
    if not (cfg) then
      return 500, { }, "Erreur config : " .. tostring(err)
    end
    local current = (cfg.filter or { })[section_key] or { }
    local section_title = "Filtre — " .. tostring(title)
    local body
    if section_key == "times" then
      body = render_times_editor(current)
    else
      body = render_kv_editor(section_key, title, desc, value_label, current, value_hint)
    end
    return 200, {
      ["Content-Type"] = "text/html; charset=UTF-8"
    }, page(section_title, body)
  end
end
local handle_nets_get = make_get("nets", "Réseaux nommés", "Groupes de CIDRs IPv4/IPv6 réutilisables dans les conditions.", "CIDRs (un par ligne)", "ex: 192.168.0.0/16")
local handle_macs_get = make_get("macs", "MACs nommées", "Groupes d'adresses MAC réutilisables.", "MACs (une par ligne)", "ex: aa:bb:cc:dd:ee:ff")
local handle_users_get = make_get("users", "Utilisateurs", "Associe un alias court à un email d'authentification.", "Email", "ex: alice@example.com")
local handle_times_get
handle_times_get = function(req, state)
  local cfg, err = read_config(state.config_path)
  if not (cfg) then
    return 500, { }, "Erreur config : " .. tostring(err)
  end
  local current = (cfg.filter or { }).times or { }
  local body = render_times_editor(current)
  return 200, {
    ["Content-Type"] = "text/html; charset=UTF-8"
  }, page("Filtre — Plages horaires", body)
end
local split_lines
split_lines = function(s)
  local items = { }
  for line in (s or ""):gmatch("[^\n]+") do
    line = line:match("^%s*(.-)%s*$")
    if not (line == "") then
      items[#items + 1] = line
    end
  end
  return items
end
local make_post
make_post = function(section_key, is_list_value)
  return function(req, state)
    local form = parse_form(req.body)
    local cfg, err = read_config(state.config_path)
    if not (cfg) then
      return 500, { }, "Erreur config : " .. tostring(err)
    end
    cfg.filter = cfg.filter or { }
    if form.delete then
      local current = cfg.filter[section_key] or { }
      current[form.delete] = nil
      cfg.filter[section_key] = current
      local ok, e = write_config(cfg, state.config_path)
      if not (ok) then
        return 500, { }, "Erreur écriture : " .. tostring(e)
      end
      return 302, {
        ["Location"] = "/admin/config/filter/" .. tostring(section_key)
      }, ""
    end
    local multi = parse_form_multi(req.body)
    local keys = multi["key[]"] or { }
    local vals = multi["val[]"] or { }
    local result = { }
    for i, k in ipairs(keys) do
      local _continue_0 = false
      repeat
        k = k:match("^%s*(.-)%s*$")
        if k == "" then
          _continue_0 = true
          break
        end
        if is_list_value then
          local items = split_lines(vals[i])
          if #items > 0 then
            result[k] = items
          end
        else
          result[k] = (vals[i] or ""):match("^%s*(.-)%s*$")
        end
        _continue_0 = true
      until true
      if not _continue_0 then
        break
      end
    end
    if form.newkey and form.newkey:match("%S") then
      local new_k = form.newkey:match("^%s*(.-)%s*$")
      if is_list_value then
        local items = split_lines(form.newval)
        if #items > 0 then
          result[new_k] = items
        end
      else
        result[new_k] = (form.newval or ""):match("^%s*(.-)%s*$")
      end
    end
    cfg.filter[section_key] = result
    local ok, e = write_config(cfg, state.config_path)
    if not (ok) then
      return 500, { }, "Erreur écriture : " .. tostring(e)
    end
    return 302, {
      ["Location"] = "/admin/config/filter/" .. tostring(section_key)
    }, ""
  end
end
local handle_nets_post = make_post("nets", true)
local handle_macs_post = make_post("macs", true)
local handle_users_post = make_post("users", false)
local handle_times_post
handle_times_post = function(req, state)
  local form = parse_form(req.body)
  local cfg, err = read_config(state.config_path)
  if not (cfg) then
    return 500, { }, "Erreur config : " .. tostring(err)
  end
  cfg.filter = cfg.filter or { }
  if form.delete then
    local current = cfg.filter.times or { }
    current[form.delete] = nil
    cfg.filter.times = current
    local ok, e = write_config(cfg, state.config_path)
    if not (ok) then
      return 500, { }, "Erreur écriture : " .. tostring(e)
    end
    return 302, {
      ["Location"] = "/admin/config/filter/times"
    }, ""
  end
  local multi = parse_form_multi(req.body)
  local keys = multi["key[]"] or { }
  local starts = multi["start[]"] or { }
  local ends = multi["end[]"] or { }
  local times = { }
  for i, k in ipairs(keys) do
    local _continue_0 = false
    repeat
      k = k:match("^%s*(.-)%s*$")
      if k == "" then
        _continue_0 = true
        break
      end
      times[k] = {
        starts[i] or "00:00",
        ends[i] or "00:00"
      }
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  if form.newkey and form.newkey:match("%S") then
    local k = form.newkey:match("^%s*(.-)%s*$")
    times[k] = {
      form.newstart or "00:00",
      form.newend or "00:00"
    }
  end
  cfg.filter.times = times
  local ok, e = write_config(cfg, state.config_path)
  if not (ok) then
    return 500, { }, "Erreur écriture : " .. tostring(e)
  end
  return 302, {
    ["Location"] = "/admin/config/filter/times"
  }, ""
end
local handle_decision_get
handle_decision_get = function(req, state)
  local cfg, err = read_config(state.config_path)
  if not (cfg) then
    return 500, { }, "Erreur config : " .. tostring(err)
  end
  local d = (cfg.filter or { }).decision or { }
  local body = H.section({
    H.h2("Politique de décision"),
    H.form({
      method = "POST",
      action = "/admin/config/filter/decision"
    }, H.div({
      H.label("Première règle gagne (first-match)"),
      H.input({
        type = "checkbox",
        name = "fmw",
        value = "1",
        checked = (d.first_match_wins ~= false) and "checked" or nil
      }),
      H.input({
        type = "hidden",
        name = "fmw_present",
        value = "1"
      })
    })),
    H.div({
      H.label("Continuer après match"),
      H.input({
        type = "checkbox",
        name = "ctn",
        value = "1",
        checked = d.continue_to_next_rule and "checked" or nil
      }),
      H.input({
        type = "hidden",
        name = "ctn_present",
        value = "1"
      })
    }),
    H.div({
      style = "margin-top:.75rem"
    }, H.button({
      type = "submit"
    }, "Enregistrer"))
  })
  return 200, {
    ["Content-Type"] = "text/html; charset=UTF-8"
  }, page("Filtre — Décision", body)
end
local handle_decision_post
handle_decision_post = function(req, state)
  local form = parse_form(req.body)
  local cfg, err = read_config(state.config_path)
  if not (cfg) then
    return 500, { }, "Erreur config : " .. tostring(err)
  end
  cfg.filter = cfg.filter or { }
  cfg.filter.decision = cfg.filter.decision or { }
  cfg.filter.decision.first_match_wins = form.fmw == "1"
  cfg.filter.decision.continue_to_next_rule = form.ctn == "1"
  local ok, e = write_config(cfg, state.config_path)
  if not (ok) then
    return 500, { }, "Erreur écriture : " .. tostring(e)
  end
  return 302, {
    ["Location"] = "/admin/config/filter/decision"
  }, ""
end
return {
  handle_nets_get = handle_nets_get,
  handle_nets_post = handle_nets_post,
  handle_macs_get = handle_macs_get,
  handle_macs_post = handle_macs_post,
  handle_users_get = handle_users_get,
  handle_users_post = handle_users_post,
  handle_times_get = handle_times_get,
  handle_times_post = handle_times_post,
  handle_decision_get = handle_decision_get,
  handle_decision_post = handle_decision_post
}
