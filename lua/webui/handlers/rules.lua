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
    local cond_cell
    if conds_str ~= "" then
      cond_cell = conds_str
    else
      cond_cell = H.em("(toujours)")
    end
    local btn_move = H.form({
      method = "POST",
      action = "/admin/config/filter/rules/" .. tostring(i) .. "/move",
      style = "display:inline"
    }, {
      H.button({
        type = "submit",
        name = "dir",
        value = "up",
        class = "btn btn-secondary btn-sm"
      }, "↑") .. H.button({
        type = "submit",
        name = "dir",
        value = "down",
        class = "btn btn-secondary btn-sm"
      }, "↓")
    })
    local btn_del = H.form({
      method = "POST",
      action = "/admin/config/filter/rules/" .. tostring(i) .. "/delete",
      style = "display:inline"
    }, {
      H.button({
        type = "submit",
        class = "btn btn-danger btn-sm",
        onclick = "return confirm('Supprimer ?')"
      }, "✕")
    })
    local btn_edit = H.a({
      class = "btn btn-secondary btn-sm",
      href = "/admin/config/filter/rules/" .. tostring(i) .. "/edit"
    }, "Éditer")
    rows = rows .. H.tr({
      H.td(tostring(i)),
      H.td(desc),
      H.td({
        class = "mono"
      }, cond_cell),
      H.td({
        class = "mono"
      }, acts_str),
      H.td({
        class = "actions"
      }, btn_edit .. " " .. btn_move .. " " .. btn_del)
    })
  end
  local thead = H.thead({
    H.tr({
      H.th({
        style = "width:2.5rem"
      }, "#"),
      H.th({
        style = "width:20%"
      }, "Description"),
      H.th("Conditions"),
      H.th({
        style = "width:12%"
      }, "Action"),
      H.th({
        style = "width:11rem"
      }, "")
    })
  })
  local tbl = H.table((thead .. H.tbody(rows)))
  local body = H.section({
    H.h2("Règles de filtrage"),
    H.p({
      H.a({
        class = "btn",
        href = "/admin/config/filter/rules/new"
      }, "Ajouter une règle")
    }),
    tbl
  })
  return 200, {
    ["Content-Type"] = "text/html; charset=UTF-8"
  }, page("Règles de filtrage", body)
end
local cond_val_str
cond_val_str = function(cval)
  if type(cval) == "table" then
    return table.concat(cval, "\n")
  elseif cval then
    return tostring(cval)
  else
    return ""
  end
end
local FORM_SUFFIX = {
  base = "",
  plural = "s",
  list = "_list",
  lists = "_lists"
}
local fam_by_root
fam_by_root = function(families, root)
  for _index_0 = 1, #families do
    local f = families[_index_0]
    if f.root == root then
      return f
    end
  end
  return families[1]
end
local cond_a_select
cond_a_select = function(families, idx, sel_root)
  local parts = { }
  local cur_cat = nil
  for _index_0 = 1, #families do
    local f = families[_index_0]
    if f.category ~= cur_cat then
      if cur_cat ~= nil then
        parts[#parts + 1] = "</optgroup>"
      end
      parts[#parts + 1] = "<optgroup label=\"" .. tostring(registry.category_label(f.category)) .. "\">"
      cur_cat = f.category
    end
    local sel
    if f.root == sel_root then
      sel = "selected"
    else
      sel = nil
    end
    parts[#parts + 1] = H.option({
      value = f.root,
      selected = sel,
      title = (f.description or "")
    }, f.label)
  end
  if cur_cat ~= nil then
    parts[#parts + 1] = "</optgroup>"
  end
  return H.select({
    class = "cond-a",
    name = "cond_" .. tostring(idx) .. "[base]",
    onchange = "_famChange(this)"
  }, table.concat(parts))
end
local cond_b_select
cond_b_select = function(fam, idx, sel_form)
  local parts = { }
  local _list_0 = fam.forms
  for _index_0 = 1, #_list_0 do
    local fm = _list_0[_index_0]
    local sel
    if fm.key == sel_form then
      sel = "selected"
    else
      sel = nil
    end
    parts[#parts + 1] = H.option({
      value = fm.key,
      selected = sel,
      title = (fm.description or "")
    }, fm.label)
  end
  local hidden = #fam.forms <= 1
  return H.select({
    class = "cond-b",
    name = "cond_" .. tostring(idx) .. "[form]",
    onchange = "_formChange(this)",
    style = hidden and "display:none" or nil
  }, table.concat(parts))
end
local render_cond_row
render_cond_row = function(families, idx, root, form, value)
  root = root or families[1].root
  local fam = fam_by_root(families, root)
  form = form or "base"
  local a = cond_a_select(families, idx, root)
  local b = cond_b_select(fam, idx, form)
  local ta = H.textarea({
    class = "cond-value",
    name = "cond_" .. tostring(idx) .. "[value]",
    rows = "2"
  }, cond_val_str(value))
  local help = H.div({
    class = "cond-help",
    style = "color:#555;font-size:.85em;margin-top:.2rem"
  }, "")
  local links = H.div({
    class = "cond-links",
    style = "font-size:.85em;margin-top:.2rem"
  }, "")
  local btn = H.button({
    type = "button",
    onclick = "_delCond(this)",
    class = "btn btn-danger btn-sm"
  }, "✕")
  return H.tr((H.td(a .. b) .. H.td({
    class = "cond-val"
  }, ta .. help .. links) .. H.td(btn)))
end
local jq
jq = function(s)
  s = tostring(s or "")
  s = s:gsub("\\", "\\\\"):gsub("\"", "\\\""):gsub("\n", "\\n"):gsub("\r", "")
  return "\"" .. tostring(s) .. "\""
end
local cond_families_js
cond_families_js = function(families)
  local fam_parts = { }
  for _index_0 = 1, #families do
    local f = families[_index_0]
    local form_parts = { }
    local _list_0 = f.forms
    for _index_1 = 1, #_list_0 do
      local fm = _list_0[_index_1]
      local lt = fm.list_type and jq(fm.list_type) or "null"
      form_parts[#form_parts + 1] = "{k:" .. tostring(jq(fm.key)) .. ",lbl:" .. tostring(jq(fm.label)) .. ",hint:" .. tostring(jq(fm.hint or '')) .. ",desc:" .. tostring(jq(fm.description or '')) .. ",lt:" .. tostring(lt) .. "}"
    end
    fam_parts[#fam_parts + 1] = tostring(jq(f.root)) .. ":{forms:[" .. tostring(table.concat(form_parts, ',')) .. "]}"
  end
  return "{" .. tostring(table.concat(fam_parts, ',')) .. "}"
end
local action_options
action_options = function(acts, current_type)
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
  return opts
end
local render_action_row
render_action_row = function(acts, idx, atype, aopts)
  local show
  show = function(t)
    return atype == t and nil or "display:none"
  end
  local rr_val = (type(aopts) == "table" and aopts.rr_type) or "A"
  local msg_val = (type(aopts) == "table" and aopts.log_msg) or ""
  local type_sel = H.select({
    class = "act-type",
    name = "action_" .. tostring(idx) .. "[type]",
    onchange = "_actChange(this)"
  }, action_options(acts, atype))
  local dns_extra = H.div({
    class = "act-dns",
    style = show("dns_strip")
  }, {
    H.label("Type d'enregistrement à supprimer"),
    H.select({
      name = "action_" .. tostring(idx) .. "[rr_type]"
    }, {
      H.option({
        value = "A",
        selected = rr_val == "A" and "selected" or nil
      }, "A (IPv4)"),
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
  })
  local log_extra = H.div({
    class = "act-log",
    style = show("log")
  }, {
    H.label("Message de log (optionnel)"),
    H.input({
      type = "text",
      name = "action_" .. tostring(idx) .. "[log_msg]",
      value = msg_val
    })
  })
  local btn = H.button({
    type = "button",
    onclick = "_delAction(this)",
    class = "btn btn-danger btn-sm"
  }, "✕")
  return H.tr((H.td(type_sel) .. H.td({
    class = "act-params"
  }, dns_extra .. log_extra) .. H.td(btn)))
end
local render_rule_form
render_rule_form = function(action_url, rule)
  rule = rule or { }
  local conds = rule.conditions or { }
  local actions = rule.actions or { }
  local desc_html = H.div({
    H.label("Description"),
    H.input({
      type = "text",
      name = "description",
      value = rule.description or ""
    })
  })
  local families = registry.condition_families()
  local cond_rows = ""
  local idx = 0
  for ctype, cval in pairs(conds) do
    local root, form = registry.resolve_condition(ctype)
    cond_rows = cond_rows .. render_cond_row(families, idx, root, form, cval)
    idx = idx + 1
  end
  local tpl_row = render_cond_row(families, "__I__", nil, nil, nil)
  local cond_tpl = H.template({
    id = "cond-tpl"
  }, tpl_row)
  local cond_thead = H.thead({
    H.tr({
      H.th("Type de condition"),
      H.th("Valeur"),
      H.th({
        style = "width:3rem"
      }, "")
    })
  })
  local cond_tbody = H.tbody({
    id = "cond-body"
  }, cond_rows)
  local cond_table = H.table((cond_thead .. cond_tbody))
  local add_btn = H.button({
    type = "button",
    onclick = "_addCond()",
    class = "btn btn-secondary btn-sm",
    style = "margin:.4rem 0 .75rem"
  }, "+ Ajouter une condition")
  local js = "var _FAM=" .. tostring(cond_families_js(families)) .. ";" .. "function _rebuildB(row){var a=row.querySelector('.cond-a'),b=row.querySelector('.cond-b');" .. "var fam=_FAM[a.value];if(!fam)return;b.innerHTML='';fam.forms.forEach(function(f){" .. "var o=document.createElement('option');o.value=f.k;o.textContent=f.lbl;if(f.desc)o.title=f.desc;b.appendChild(o);});" .. "b.style.display=fam.forms.length<=1?'none':'';}" .. "function _applyForm(row){var a=row.querySelector('.cond-a'),b=row.querySelector('.cond-b');" .. "var ta=row.querySelector('.cond-value'),help=row.querySelector('.cond-help');" .. "var fam=_FAM[a.value];if(!fam)return;var fk=b.value||'base',f=null;" .. "fam.forms.forEach(function(x){if(x.k===fk)f=x;});if(!f)f=fam.forms[0];if(!f)return;" .. "ta.placeholder=f.hint||'';help.textContent=f.desc||'';" .. "row._lt=(f.k==='list'||f.k==='lists')?f.lt:null;_renderLinks(row);}" .. "function _renderLinks(row){var links=row.querySelector('.cond-links');" .. "var ta=row.querySelector('.cond-value');links.innerHTML='';if(!row._lt)return;" .. "ta.value.split('\\n').forEach(function(line){var n=line.trim();if(!n)return;" .. "var a=document.createElement('a');a.href='/admin/config/filter/lists/'+" .. "encodeURIComponent(row._lt)+'/'+encodeURIComponent(n);a.target='_blank';a.rel='noopener';" .. "a.textContent='\\u270e '+n;a.style.marginRight='.6rem';links.appendChild(a);});}" .. "function _famChange(sel){var row=sel.closest('tr');_rebuildB(row);_applyForm(row);}" .. "function _formChange(sel){_applyForm(sel.closest('tr'));}" .. "var _ci=" .. tostring(idx) .. ";function _addCond(){" .. "var t=document.getElementById('cond-tpl').content.cloneNode(true).querySelector('tr');" .. "t.querySelectorAll('[name]').forEach(function(e){e.name=e.name.replace('__I__',_ci);});" .. "_ci++;var body=document.getElementById('cond-body');body.appendChild(t);" .. "_applyForm(body.lastElementChild);}" .. "function _delCond(b){b.closest('tr').remove();}" .. "document.getElementById('cond-body').addEventListener('input',function(e){" .. "if(e.target.classList.contains('cond-value'))_renderLinks(e.target.closest('tr'));});" .. "Array.prototype.forEach.call(document.querySelectorAll('#cond-body tr'),_applyForm);"
  local acts_reg = registry.actions()
  local resolve_action
  resolve_action = function(a)
    if type(a) == "string" then
      return a, nil
    elseif type(a) == "table" then
      for k, v in pairs(a) do
        return k, v
      end
      return nil, nil
    else
      return nil, nil
    end
  end
  local action_rows = ""
  local ai = 0
  for _index_0 = 1, #actions do
    local a = actions[_index_0]
    local at, ao = resolve_action(a)
    action_rows = action_rows .. render_action_row(acts_reg, ai, at, ao)
    ai = ai + 1
  end
  if ai == 0 then
    action_rows = render_action_row(acts_reg, 0, nil, nil)
    ai = 1
  end
  local act_tpl_row = render_action_row(acts_reg, "__I__", nil, nil)
  local act_tpl = H.template({
    id = "act-tpl"
  }, act_tpl_row)
  local act_thead = H.thead({
    H.tr({
      H.th("Action"),
      H.th("Paramètres"),
      H.th({
        style = "width:3rem"
      }, "")
    })
  })
  local act_tbody = H.tbody({
    id = "act-body"
  }, action_rows)
  local act_table = H.table((act_thead .. act_tbody))
  local act_add_btn = H.button({
    type = "button",
    onclick = "_addAction()",
    class = "btn btn-secondary btn-sm",
    style = "margin:.4rem 0 .75rem"
  }, "+ Ajouter une action")
  local act_js = "function _actChange(sel){var row=sel.closest('tr');var t=sel.value;" .. "var d=row.querySelector('.act-dns'),l=row.querySelector('.act-log');" .. "if(d)d.style.display=(t==='dns_strip')?'':'none';" .. "if(l)l.style.display=(t==='log')?'':'none';}" .. "var _ai=" .. tostring(ai) .. ";function _addAction(){" .. "var t=document.getElementById('act-tpl').content.cloneNode(true).querySelector('tr');" .. "t.querySelectorAll('[name]').forEach(function(e){e.name=e.name.replace('__I__',_ai);});" .. "_ai++;var body=document.getElementById('act-body');body.appendChild(t);" .. "_actChange(body.lastElementChild.querySelector('.act-type'));}" .. "function _delAction(b){var body=document.getElementById('act-body');" .. "if(body.rows.length>1)b.closest('tr').remove();}" .. "Array.prototype.forEach.call(document.querySelectorAll('#act-body .act-type'),_actChange);"
  local buttons = H.div({
    style = "margin-top:1rem"
  }, {
    H.button({
      type = "submit"
    }, "Enregistrer") .. " " .. H.a({
      class = "btn btn-secondary",
      href = "/admin/config/filter/rules"
    }, "Annuler")
  })
  local body_html = desc_html .. H.h3("Conditions — toutes en AND") .. cond_tpl .. cond_table .. add_btn .. H.h3("Actions — appliquées dans l'ordre") .. act_tpl .. act_table .. act_add_btn .. buttons .. H.script(js) .. H.script(act_js)
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
  local conds_reg = registry.conditions()
  for i = 0, 49 do
    local _continue_0 = false
    repeat
      local base = form["cond_" .. tostring(i) .. "[base]"]
      local fkey = form["cond_" .. tostring(i) .. "[form]"] or "base"
      local cval = form["cond_" .. tostring(i) .. "[value]"] or ""
      if not (base and base ~= "") then
        _continue_0 = true
        break
      end
      if not (cval:match("%S")) then
        _continue_0 = true
        break
      end
      local ctype = base .. (FORM_SUFFIX[fkey] or "")
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
  local build_action
  build_action = function(prefix)
    local atype = form[tostring(prefix) .. "[type]"]
    if not (atype and atype ~= "") then
      return nil
    end
    if atype == "dns_strip" then
      return {
        dns_strip = {
          rr_type = form[tostring(prefix) .. "[rr_type]"] or "A"
        }
      }
    elseif atype == "log" then
      return {
        log = {
          log_msg = form[tostring(prefix) .. "[log_msg]"] or ""
        }
      }
    else
      return atype
    end
  end
  local actions = { }
  for i = 0, 49 do
    local a = build_action("action_" .. tostring(i))
    if a then
      actions[#actions + 1] = a
    end
  end
  if #actions == 0 then
    local a = build_action("action")
    if a then
      actions[#actions + 1] = a
    end
  end
  if #actions > 0 then
    rule.actions = actions
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
