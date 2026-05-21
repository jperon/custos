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
local registry = require("webui.schema.registry")
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
local rule_summary
rule_summary = function(rule)
  local desc = rule.description or "(sans titre)"
  local conds_parts = { }
  if rule.conditions then
    for k, v in pairs(rule.conditions) do
      local val_str
      if type(v) == "table" then
        val_str = "[" .. table.concat((function()
          local _accum_0 = { }
          local _len_0 = 1
          for _index_0 = 1, #v do
            local i = v[_index_0]
            _accum_0[_len_0] = tostring(i)
            _len_0 = _len_0 + 1
          end
          return _accum_0
        end)(), ", ") .. "]"
      else
        val_str = tostring(v)
      end
      conds_parts[#conds_parts + 1] = tostring(k) .. ": " .. tostring(val_str)
    end
  end
  local acts_parts = { }
  if rule.actions then
    for _, a in ipairs(rule.actions) do
      if type(a) == "table" then
        local next_k = nil
        for k in pairs(a) do
          next_k = k
          break
        end
        acts_parts[#acts_parts + 1] = next_k or "?"
      else
        acts_parts[#acts_parts + 1] = tostring(a)
      end
    end
  end
  return desc, table.concat(conds_parts, " AND "), table.concat(acts_parts, ", ")
end
local handle_rules_list
handle_rules_list = function(req, state)
  local cfg, err = read_config(state.config_path)
  if not (cfg) then
    return 500, { }, "Erreur config : " .. tostring(err)
  end
  local rules = (cfg.filter or { }).rules or { }
  local rows = ""
  for i, rule in ipairs(rules) do
    local desc, conds_str, acts_str = rule_summary(rule)
    rows = rows .. H.li({
      H.span({
        class = "rule-desc"
      }, H.strong(desc)),
      H.br(),
      H.span({
        class = "rule-cond"
      }, (conds_str ~= "" and "SI " .. conds_str or "(toujours)")),
      " → ",
      H.span({
        class = "rule-action"
      }, acts_str),
      H.a({
        class = "btn btn-secondary btn-sm",
        href = "/admin/config/filter/rules/" .. tostring(i) .. "/edit"
      }, "Éditer"),
      H.form({
        method = "POST",
        action = "/admin/config/filter/rules/" .. tostring(i) .. "/move",
        style = "display:inline"
      }, H.button({
        type = "submit",
        name = "dir",
        value = "up",
        class = "btn btn-secondary btn-sm"
      }, "↑")),
      H.button({
        type = "submit",
        name = "dir",
        value = "down",
        class = "btn btn-secondary btn-sm"
      }, "↓"),
      H.form({
        method = "POST",
        action = "/admin/config/filter/rules/" .. tostring(i) .. "/delete",
        style = "display:inline"
      }, H.button({
        type = "submit",
        class = "btn btn-danger btn-sm",
        onclick = "return confirm('Supprimer cette règle ?')"
      }, "✕"))
    })
  end
  local body = H.section({
    H.h2("Règles de filtrage"),
    H.p({
      H.a({
        class = "btn",
        href = "/admin/config/filter/rules/new"
      }, "Ajouter une règle")
    }),
    H.ul({
      class = "rule-list"
    }, rows)
  })
  return 200, {
    ["Content-Type"] = "text/html; charset=UTF-8"
  }, page("Règles de filtrage", body)
end
local render_condition_select
render_condition_select = function(prefix, current_type, current_val)
  local conds = registry.conditions()
  local ordered = { }
  for name, s in pairs(conds) do
    ordered[#ordered + 1] = {
      name,
      s
    }
  end
  table.sort(ordered, function(a, b)
    local ca = a[2].category or "z"
    local cb = b[2].category or "z"
    if ca == cb then
      return a[2].label < b[2].label
    else
      return ca < cb
    end
  end)
  local opts = ""
  for _, pair in ipairs(ordered) do
    local name, s = pair[1], pair[2]
    local sel
    if name == current_type then
      sel = "selected"
    else
      sel = nil
    end
    opts = opts .. H.option({
      value = name,
      selected = sel
    }, (s.label or name))
  end
  local sel_id = prefix .. "_type"
  local fieldsets = ""
  for _, pair in ipairs(ordered) do
    local name, s = pair[1], pair[2]
    local fid = prefix .. "_fields_" .. name:gsub("[^%w]", "_")
    local display
    if name == current_type then
      display = ""
    else
      display = "display:none"
    end
    local field_input = render_condition_input(prefix, name, s, current_val)
    fieldsets = fieldsets .. H.div({
      id = fid,
      style = display
    }, field_input)
  end
  local js = [[    document.getElementById(']] .. sel_id .. [[').addEventListener('change', function() {
      var val = this.value;
      var prefix = ']] .. prefix .. [[';
      document.querySelectorAll('[id^="' + prefix + '_fields_"]').forEach(function(el) {
        el.style.display = 'none';
      });
      var target = document.getElementById(prefix + '_fields_' + val.replace(/[^a-zA-Z0-9]/g, '_'));
      if (target) target.style.display = '';
    });
  ]]
  return H.div({
    H.label("Type de condition"),
    H.select({
      id = sel_id,
      name = prefix .. "[type]"
    }, opts),
    fieldsets,
    H.script(js)
  })
end
local render_condition_input
render_condition_input = function(prefix, cond_name, schema, current_val)
  local t = schema and schema.arg_type
  if not (t) then
    return ""
  end
  local fname = prefix .. "[value]"
  local hint = schema.arg_hint or ""
  if t == "string" or t == "string_or_table" then
    local val
    if type(current_val) == "string" then
      val = current_val
    else
      val = ""
    end
    return H.div({
      H.label((schema.label or cond_name) .. " — valeur"),
      H.input({
        type = "text",
        name = fname,
        value = val,
        placeholder = hint
      })
    })
  elseif t == "integer" then
    local val
    if type(current_val) == "number" then
      val = tostring(current_val)
    else
      val = ""
    end
    return H.div({
      H.label((schema.label or cond_name)),
      H.input({
        type = "number",
        name = fname,
        value = val,
        placeholder = hint
      })
    })
  elseif t == "string_list" then
    local val
    if type(current_val) == "table" then
      val = table.concat(current_val, "\n")
    elseif type(current_val) == "string" then
      val = current_val
    else
      val = ""
    end
    return H.div({
      H.label((schema.label or cond_name) .. " (une valeur par ligne)"),
      H.textarea({
        name = fname,
        rows = "3"
      }, val)
    })
  elseif t == "condition_list" or t == "condition" then
    return H.div({
      H.p({
        style = "color:#888;font-style:italic"
      }, "Édition manuelle requise pour les méta-conditions."),
      H.input({
        type = "text",
        name = fname,
        value = ""
      })
    })
  end
  return ""
end
local render_action_select
render_action_select = function(prefix, current_type, current_opts)
  local acts = registry.actions()
  local opts = ""
  for name, s in pairs(acts) do
    local sel
    if name == current_type then
      sel = "selected"
    else
      sel = nil
    end
    opts = opts .. H.option({
      value = name,
      selected = sel
    }, (s and s.label or name))
  end
  local extra = ""
  if current_type == "dns_strip" then
    local rr_val
    if type(current_opts) == "table" then
      rr_val = current_opts.rr_type or "A"
    else
      rr_val = "A"
    end
    extra = H.div({
      H.label("Type d'enregistrement à supprimer"),
      H.select({
        name = prefix .. "[rr_type]"
      }, H.option({
        value = "A",
        selected = rr_val == "A" and "selected" or nil
      }, "A (IPv4)")),
      H.option({
        value = "AAAA",
        selected = rr_val == "AAAA" and "selected" or nil
      }, "AAAA (IPv6)"),
      H.option({
        value = "CNAME",
        selected = rr_val == "CNAME" and "selected" or nil
      }, "CNAME"),
      H.option({
        value = "MX",
        selected = rr_val == "MX" and "selected" or nil
      }, "MX")
    })
  elseif current_type == "log" then
    local msg_val
    if type(current_opts) == "table" then
      msg_val = current_opts.log_msg or ""
    else
      msg_val = ""
    end
    extra = H.div({
      H.label("Message de log (optionnel)"),
      H.input({
        type = "text",
        name = prefix .. "[log_msg]",
        value = msg_val
      })
    })
  end
  return H.div({
    H.label("Action"),
    H.select({
      name = prefix .. "[type]"
    }, opts),
    extra
  })
end
local render_rule_form
render_rule_form = function(action_url, rule)
  rule = rule or { }
  local conds = rule.conditions or { }
  local actions = rule.actions or { }
  local desc_field = H.div({
    H.label("Description"),
    H.input({
      type = "text",
      name = "description",
      value = rule.description or ""
    })
  })
  local cond_fields = ""
  for i = 1, 5 do
    local cond_key = next(conds)
    local cond_type, cond_val = nil, nil
    local j = 0
    for k, v in pairs(conds) do
      j = j + 1
      if j == i then
        cond_type, cond_val = k, v
        break
      end
    end
    cond_fields = cond_fields .. H.fieldset({
      H.legend("Condition " .. tostring(i) .. " (optionnelle)"),
      render_condition_select("cond_" .. tostring(i), cond_type, cond_val)
    })
  end
  local action_type = nil
  local action_opts = nil
  if #actions > 0 then
    local first = actions[1]
    if type(first) == "string" then
      action_type = first
    elseif type(first) == "table" then
      for k in pairs(first) do
        action_type = k
        action_opts = first[k]
        break
      end
    end
  end
  local action_field = H.fieldset({
    H.legend("Action"),
    render_action_select("action", action_type, action_opts)
  })
  local body_html = desc_field .. H.h3("Conditions — toutes en AND") .. cond_fields .. H.h3("Action") .. action_field .. H.div({
    style = "margin-top:1rem"
  }, H.button({
    type = "submit"
  }, "Enregistrer") .. " " .. H.a({
    class = "btn btn-secondary",
    href = "/admin/config/filter/rules"
  }, "Annuler"))
  return H.form({
    method = "POST",
    action = action_url
  }, body_html)
end
local rebuild_rule
rebuild_rule = function(form)
  local rule = { }
  rule.description = form.description or ""
  local conditions = { }
  for i = 1, 5 do
    local _continue_0 = false
    repeat
      local ctype = form["cond_" .. tostring(i) .. "[type]"]
      local cval = form["cond_" .. tostring(i) .. "[value]"]
      if not (ctype and ctype ~= "") then
        _continue_0 = true
        break
      end
      if not (cval and cval:match("%S")) then
        _continue_0 = true
        break
      end
      local conds_reg = registry.conditions()
      local s = conds_reg[ctype]
      if s and s.arg_type == "string_list" then
        local items = { }
        for line in cval:gmatch("[^\n]+") do
          line = line:match("^%s*(.-)%s*$")
          if not (line == "") then
            items[#items + 1] = line
          end
        end
        if #items > 0 then
          conditions[ctype] = items
        end
      elseif s and s.arg_type == "integer" then
        conditions[ctype] = tonumber(cval)
      else
        conditions[ctype] = cval:match("^%s*(.-)%s*$")
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  if next(conditions) then
    rule.conditions = conditions
  end
  local atype = form["action[type]"]
  if atype and atype ~= "" then
    if atype == "dns_strip" then
      rule.actions = {
        {
          dns_strip = {
            rr_type = form["action[rr_type]"] or "A"
          }
        }
      }
    elseif atype == "log" then
      local msg = form["action[log_msg]"] or ""
      rule.actions = {
        {
          log = {
            log_msg = msg
          }
        }
      }
    else
      rule.actions = {
        atype
      }
    end
  end
  return rule
end
local handle_rules_new_get
handle_rules_new_get = function(req, state)
  local body = H.section({
    H.h2("Nouvelle règle"),
    render_rule_form("/admin/config/filter/rules/new", nil)
  })
  return 200, {
    ["Content-Type"] = "text/html; charset=UTF-8"
  }, page("Nouvelle règle", body)
end
local handle_rules_new_post
handle_rules_new_post = function(req, state)
  local form = parse_form(req.body)
  local cfg, err = read_config(state.config_path)
  if not (cfg) then
    return 500, { }, "Erreur config : " .. tostring(err)
  end
  cfg.filter = cfg.filter or { }
  cfg.filter.rules = cfg.filter.rules or { }
  local rule = rebuild_rule(form)
  cfg.filter.rules[#cfg.filter.rules + 1] = rule
  local ok, e = write_config(cfg, state.config_path)
  if not (ok) then
    return 500, { }, "Erreur écriture : " .. tostring(e)
  end
  return 302, {
    ["Location"] = "/admin/config/filter/rules"
  }, ""
end
local handle_rules_edit_get
handle_rules_edit_get = function(req, n, state)
  local cfg, err = read_config(state.config_path)
  if not (cfg) then
    return 500, { }, "Erreur config : " .. tostring(err)
  end
  local rules = (cfg.filter or { }).rules or { }
  local rule = rules[n]
  if not (rule) then
    return 404, { }, "Règle " .. tostring(n) .. " introuvable"
  end
  local body = H.section({
    H.h2("Éditer la règle " .. tostring(n)),
    render_rule_form("/admin/config/filter/rules/" .. tostring(n) .. "/edit", rule)
  })
  return 200, {
    ["Content-Type"] = "text/html; charset=UTF-8"
  }, page("Éditer règle " .. tostring(n), body)
end
local handle_rules_edit_post
handle_rules_edit_post = function(req, n, state)
  local form = parse_form(req.body)
  local cfg, err = read_config(state.config_path)
  if not (cfg) then
    return 500, { }, "Erreur config : " .. tostring(err)
  end
  local rules = (cfg.filter or { }).rules or { }
  if not (rules[n]) then
    return 404, { }, "Règle " .. tostring(n) .. " introuvable"
  end
  rules[n] = rebuild_rule(form)
  cfg.filter.rules = rules
  local ok, e = write_config(cfg, state.config_path)
  if not (ok) then
    return 500, { }, "Erreur écriture : " .. tostring(e)
  end
  return 302, {
    ["Location"] = "/admin/config/filter/rules"
  }, ""
end
local handle_rules_delete
handle_rules_delete = function(req, n, state)
  local cfg, err = read_config(state.config_path)
  if not (cfg) then
    return 500, { }, "Erreur config : " .. tostring(err)
  end
  local rules = (cfg.filter or { }).rules or { }
  if not (rules[n]) then
    return 404, { }, "Règle " .. tostring(n) .. " introuvable"
  end
  table.remove(rules, n)
  cfg.filter.rules = rules
  local ok, e = write_config(cfg, state.config_path)
  if not (ok) then
    return 500, { }, "Erreur écriture : " .. tostring(e)
  end
  return 302, {
    ["Location"] = "/admin/config/filter/rules"
  }, ""
end
local handle_rules_move
handle_rules_move = function(req, n, state)
  local form = parse_form(req.body)
  local dir = form.dir
  local cfg, err = read_config(state.config_path)
  if not (cfg) then
    return 500, { }, "Erreur config : " .. tostring(err)
  end
  local rules = (cfg.filter or { }).rules or { }
  if not (rules[n]) then
    return 404, { }, "Règle " .. tostring(n) .. " introuvable"
  end
  local other
  if dir == "up" then
    other = n - 1
  else
    other = n + 1
  end
  if rules[other] then
    rules[n], rules[other] = rules[other], rules[n]
    cfg.filter.rules = rules
    local ok, e = write_config(cfg, state.config_path)
    if not (ok) then
      return 500, { }, "Erreur écriture : " .. tostring(e)
    end
  end
  return 302, {
    ["Location"] = "/admin/config/filter/rules"
  }, ""
end
return {
  handle_rules_list = handle_rules_list,
  handle_rules_new_get = handle_rules_new_get,
  handle_rules_new_post = handle_rules_new_post,
  handle_rules_edit_get = handle_rules_edit_get,
  handle_rules_edit_post = handle_rules_edit_post,
  handle_rules_delete = handle_rules_delete,
  handle_rules_move = handle_rules_move
}
