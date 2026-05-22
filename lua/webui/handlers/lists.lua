local H = require("auth.html")
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
local valid_type
valid_type = function(t)
  return t and t:match("^[a-z][a-z0-9_]*$")
end
local valid_name
valid_name = function(n)
  return n and n:match("^[a-zA-Z0-9][a-zA-Z0-9_%-]*$")
end
local get_lists_dir
get_lists_dir = function(state)
  local cfg = read_config(state.config_path)
  local dir = cfg and cfg.filter and cfg.filter.lists_dir
  dir = dir or (cfg and cfg.lists_dir)
  return dir or "/etc/custos/lists"
end
local scan_types
scan_types = function(lists_dir)
  local types = { }
  local f = io.popen("find '" .. tostring(lists_dir) .. "' -maxdepth 1 -mindepth 1 -type d 2>/dev/null")
  if not (f) then
    return types
  end
  for line in f:lines() do
    local t = line:match("/([^/]+)$")
    if valid_type(t) then
      types[#types + 1] = t
    end
  end
  f:close()
  table.sort(types)
  return types
end
local scan_names
scan_names = function(lists_dir, type_name)
  local names = { }
  local dir = tostring(lists_dir) .. "/" .. tostring(type_name)
  local f = io.popen("find '" .. tostring(dir) .. "' -maxdepth 1 -name '*.txt' -type f 2>/dev/null")
  if not (f) then
    return names
  end
  for line in f:lines() do
    local n = line:match("/([^/]+)%.txt$")
    if valid_name(n) then
      names[#names + 1] = n
    end
  end
  f:close()
  table.sort(names)
  return names
end
local read_list_file
read_list_file = function(path)
  local fh = io.open(path, "r")
  if not (fh) then
    return ""
  end
  local content = fh:read("*a")
  fh:close()
  return content
end
local write_list_file
write_list_file = function(path, content)
  local dir = path:match("^(.*)/[^/]+$")
  if dir then
    local ret = os.execute("mkdir -p '" .. tostring(dir) .. "'")
    if not (ret == 0 or ret == true) then
      return nil, "mkdir échoué"
    end
  end
  local fh = io.open(path, "w")
  if not (fh) then
    return nil, "Impossible d'ouvrir " .. tostring(path) .. " en écriture"
  end
  fh:write(content)
  fh:close()
  return true
end
local update_config_refs
update_config_refs = function(cfg, type_name, old_name, new_name)
  local changed = false
  local rules = cfg.filter and cfg.filter.rules
  if not (rules) then
    return false
  end
  local suffix_single = "_" .. tostring(type_name) .. "_list"
  local suffix_multi = "_" .. tostring(type_name) .. "_lists"
  for _index_0 = 1, #rules do
    local _continue_0 = false
    repeat
      local rule = rules[_index_0]
      local conds = rule.conditions
      if not (conds) then
        _continue_0 = true
        break
      end
      for ckey, cval in pairs(conds) do
        if ckey:match(suffix_single .. "$") or ckey:match(suffix_multi .. "$") then
          if type(cval) == "string" and cval == old_name then
            conds[ckey] = new_name
            changed = true
          elseif type(cval) == "table" then
            for i, v in ipairs(cval) do
              if v == old_name then
                cval[i] = new_name
                changed = true
              end
            end
          end
        end
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  return changed
end
local handle_lists_index
handle_lists_index = function(req, state)
  local lists_dir = get_lists_dir(state)
  local types = scan_types(lists_dir)
  local items = ""
  for _index_0 = 1, #types do
    local t = types[_index_0]
    local names = scan_names(lists_dir, t)
    local n = #names
    items = items .. H.li({
      H.a({
        href = "/admin/config/filter/lists/" .. tostring(t)
      }, t),
      " — " .. tostring(n) .. " liste" .. tostring(n > 1 and 's' or '')
    })
  end
  local body = H.section({
    H.h2("Listes de filtrage"),
    H.p({
      style = "color:#555"
    }, "Répertoire : " .. H.code(lists_dir)),
    H.p({
      style = "color:#555"
    }, "Utilisées par les conditions " .. H.code("from_xxx_list") .. "."),
    (function()
      if items ~= "" then
        return H.ul({ }, items)
      else
        return H.p("Aucun type trouvé dans " .. H.code(lists_dir) .. ".")
      end
    end)(),
    H.p({
      H.a({
        class = "btn btn-secondary",
        href = "/admin/config/"
      }, "← Configuration")
    })
  })
  return 200, {
    ["Content-Type"] = "text/html; charset=UTF-8"
  }, page("Listes de filtrage", body)
end
local handle_lists_type
handle_lists_type = function(req, type_name, state)
  if not (valid_type(type_name)) then
    return 400, { }, "Type invalide"
  end
  local lists_dir = get_lists_dir(state)
  local names = scan_names(lists_dir, type_name)
  local rows = ""
  for _index_0 = 1, #names do
    local n = names[_index_0]
    rows = rows .. H.tr({
      H.td({
        H.a({
          href = "/admin/config/filter/lists/" .. tostring(type_name) .. "/" .. tostring(n)
        }, n .. ".txt")
      }),
      H.td({
        H.form({
          method = "POST",
          action = "/admin/config/filter/lists/" .. tostring(type_name) .. "/" .. tostring(n),
          style = "display:inline"
        }, H.input({
          type = "hidden",
          name = "action",
          value = "delete"
        })),
        H.button({
          type = "submit",
          class = "btn btn-danger btn-sm",
          onclick = "return confirm('Supprimer ?')"
        }, "✕")
      })
    })
  end
  local tbl
  if rows ~= "" then
    tbl = H.table({
      H.thead({
        H.tr({
          H.th("Fichier", H.th(""))
        })
      }),
      H.tbody({ }, rows)
    })
  else
    tbl = H.p("Aucune liste pour ce type.")
  end
  local body = H.section({
    H.h2("Listes — " .. tostring(type_name)),
    H.p({
      H.a({
        class = "btn btn-secondary",
        href = "/admin/config/filter/lists/" .. tostring(type_name) .. "/new"
      }, "+ Nouvelle liste")
    }),
    tbl,
    H.p({
      style = "margin-top:1rem"
    }, H.a({
      class = "btn btn-secondary",
      href = "/admin/config/filter/lists"
    }, "← Retour"))
  })
  return 200, {
    ["Content-Type"] = "text/html; charset=UTF-8"
  }, page("Listes — " .. tostring(type_name), body)
end
local handle_list_get
handle_list_get = function(req, type_name, list_name, state)
  if not (valid_type(type_name)) then
    return 400, { }, "Type invalide"
  end
  if not (valid_name(list_name)) then
    return 400, { }, "Nom invalide"
  end
  local lists_dir = get_lists_dir(state)
  local path = tostring(lists_dir) .. "/" .. tostring(type_name) .. "/" .. tostring(list_name) .. ".txt"
  local content = read_list_file(path)
  local base_url = "/admin/config/filter/lists/" .. tostring(type_name) .. "/" .. tostring(list_name)
  local edit_body = H.div({
    H.label("Contenu (un élément par ligne — les lignes vides et # commentaires sont ignorés)"),
    H.textarea({
      name = "content",
      rows = "20",
      style = "font-family:monospace;width:100%;margin-top:.25rem"
    }, content)
  }) .. H.input({
    type = "hidden",
    name = "action",
    value = "save"
  }) .. H.div({
    style = "margin-top:.75rem"
  }, H.button({
    type = "submit"
  }, "Enregistrer") .. " " .. H.a({
    class = "btn btn-secondary",
    href = "/admin/config/filter/lists/" .. tostring(type_name)
  }, "Annuler"))
  local edit_form = H.form({
    method = "POST",
    action = base_url
  }, edit_body)
  local rename_inner = H.div({
    style = "display:flex;gap:.5rem;align-items:flex-end"
  }, H.div({
    H.label("Nouveau nom"),
    H.input({
      type = "text",
      name = "new_name",
      value = list_name,
      pattern = "[a-zA-Z0-9][a-zA-Z0-9_\\-]*",
      required = "required"
    })
  }) .. H.div({ }, H.input({
    type = "hidden",
    name = "action",
    value = "rename"
  }) .. H.button({
    type = "submit"
  }, "Renommer"))) .. H.p({
    style = "color:#888;font-size:.85em;margin:.25rem 0 0"
  }, "Les références dans config.moon seront mises à jour automatiquement.")
  local rename_form = H.details({
    H.summary({
      style = "cursor:pointer;color:#555;margin-top:1.5rem"
    }, "Renommer cette liste") .. H.form({
      method = "POST",
      action = base_url,
      style = "margin-top:.5rem"
    }, rename_inner)
  })
  local body = H.section({
    H.h2(tostring(type_name) .. " / " .. tostring(list_name) .. ".txt"),
    edit_form,
    rename_form
  })
  return 200, {
    ["Content-Type"] = "text/html; charset=UTF-8"
  }, page(tostring(type_name) .. "/" .. tostring(list_name), body)
end
local handle_list_post
handle_list_post = function(req, type_name, list_name, state)
  if not (valid_type(type_name)) then
    return 400, { }, "Type invalide"
  end
  if not (valid_name(list_name)) then
    return 400, { }, "Nom invalide"
  end
  local form = parse_form(req.body)
  local lists_dir = get_lists_dir(state)
  local path = tostring(lists_dir) .. "/" .. tostring(type_name) .. "/" .. tostring(list_name) .. ".txt"
  if form.action == "delete" then
    os.remove(path)
    return 302, {
      ["Location"] = "/admin/config/filter/lists/" .. tostring(type_name)
    }, ""
  end
  if form.action == "rename" then
    local new_name = form.new_name and (form.new_name:match("^%s*(.-)%s*$")) or ""
    if not (valid_name(new_name)) then
      return 400, { }, "Nouveau nom invalide"
    end
    if new_name == list_name then
      return 302, {
        ["Location"] = "/admin/config/filter/lists/" .. tostring(type_name) .. "/" .. tostring(list_name)
      }, ""
    end
    local new_path = tostring(lists_dir) .. "/" .. tostring(type_name) .. "/" .. tostring(new_name) .. ".txt"
    local ret = os.rename(path, new_path)
    if not (ret) then
      return 500, { }, "Échec du renommage de " .. tostring(list_name) .. " → " .. tostring(new_name)
    end
    local cfg, _ = read_config(state.config_path)
    if cfg then
      local changed = update_config_refs(cfg, type_name, list_name, new_name)
      if changed then
        write_config(cfg, state.config_path)
      end
    end
    return 302, {
      ["Location"] = "/admin/config/filter/lists/" .. tostring(type_name) .. "/" .. tostring(new_name)
    }, ""
  end
  local content = form.content or ""
  local ok, e = write_list_file(path, content)
  if not (ok) then
    return 500, { }, "Erreur écriture : " .. tostring(e)
  end
  return 302, {
    ["Location"] = "/admin/config/filter/lists/" .. tostring(type_name) .. "/" .. tostring(list_name)
  }, ""
end
local handle_list_new_get
handle_list_new_get = function(req, type_name, state)
  if not (valid_type(type_name)) then
    return 400, { }, "Type invalide"
  end
  local body = H.section({
    H.h2("Nouvelle liste — " .. tostring(type_name)),
    H.form({
      method = "POST",
      action = "/admin/config/filter/lists/" .. tostring(type_name) .. "/new"
    }, H.div({
      H.label("Nom (lettres, chiffres, - et _ uniquement)"),
      H.input({
        type = "text",
        name = "name",
        placeholder = "ex: famille",
        required = "required"
      })
    })),
    H.div({
      H.label("Contenu (un élément par ligne)"),
      H.textarea({
        name = "content",
        rows = "10",
        style = "font-family:monospace;width:100%;margin-top:.25rem"
      }, "")
    }),
    H.div({
      style = "margin-top:.75rem"
    }, H.button({
      type = "submit"
    }, "Créer")),
    " ",
    H.a({
      class = "btn btn-secondary",
      href = "/admin/config/filter/lists/" .. tostring(type_name)
    }, "Annuler")
  })
  return 200, {
    ["Content-Type"] = "text/html; charset=UTF-8"
  }, page("Nouvelle liste — " .. tostring(type_name), body)
end
local handle_list_new_post
handle_list_new_post = function(req, type_name, state)
  if not (valid_type(type_name)) then
    return 400, { }, "Type invalide"
  end
  local form = parse_form(req.body)
  local list_name = form.name and (form.name:match("^%s*(.-)%s*$")) or ""
  if not (valid_name(list_name)) then
    return 400, { }, "Nom invalide"
  end
  local lists_dir = get_lists_dir(state)
  local path = tostring(lists_dir) .. "/" .. tostring(type_name) .. "/" .. tostring(list_name) .. ".txt"
  local content = form.content or ""
  local ok, e = write_list_file(path, content)
  if not (ok) then
    return 500, { }, "Erreur écriture : " .. tostring(e)
  end
  return 302, {
    ["Location"] = "/admin/config/filter/lists/" .. tostring(type_name) .. "/" .. tostring(list_name)
  }, ""
end
return {
  handle_lists_index = handle_lists_index,
  handle_lists_type = handle_lists_type,
  handle_list_get = handle_list_get,
  handle_list_post = handle_list_post,
  handle_list_new_get = handle_list_new_get,
  handle_list_new_post = handle_list_new_post
}
