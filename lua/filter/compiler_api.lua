local is_new_style
is_new_style = function(obj)
  if not (type(obj) == "table") then
    return false
  end
  if not (obj.capabilities) then
    return false
  end
  return true
end
local compute_worker_only
compute_worker_only = function(obj)
  if not (type(obj) == "table") then
    return true
  end
  if not (obj.capabilities) then
    return true
  end
  return not obj.capabilities.nft
end
local sanitize_ascii
sanitize_ascii = function(raw)
  if not (raw) then
    return ""
  end
  local s = tostring(raw)
  local replacements = {
    {
      "À",
      "A"
    },
    {
      "Á",
      "A"
    },
    {
      "Â",
      "A"
    },
    {
      "Ã",
      "A"
    },
    {
      "Ä",
      "A"
    },
    {
      "Å",
      "A"
    },
    {
      "à",
      "a"
    },
    {
      "á",
      "a"
    },
    {
      "â",
      "a"
    },
    {
      "ã",
      "a"
    },
    {
      "ä",
      "a"
    },
    {
      "å",
      "a"
    },
    {
      "È",
      "E"
    },
    {
      "É",
      "E"
    },
    {
      "Ê",
      "E"
    },
    {
      "Ë",
      "E"
    },
    {
      "è",
      "e"
    },
    {
      "é",
      "e"
    },
    {
      "ê",
      "e"
    },
    {
      "ë",
      "e"
    },
    {
      "Ì",
      "I"
    },
    {
      "Í",
      "I"
    },
    {
      "Î",
      "I"
    },
    {
      "Ï",
      "I"
    },
    {
      "ì",
      "i"
    },
    {
      "í",
      "i"
    },
    {
      "î",
      "i"
    },
    {
      "ï",
      "i"
    },
    {
      "Ò",
      "O"
    },
    {
      "Ó",
      "O"
    },
    {
      "Ô",
      "O"
    },
    {
      "Õ",
      "O"
    },
    {
      "Ö",
      "O"
    },
    {
      "ò",
      "o"
    },
    {
      "ó",
      "o"
    },
    {
      "ô",
      "o"
    },
    {
      "õ",
      "o"
    },
    {
      "ö",
      "o"
    },
    {
      "Ù",
      "U"
    },
    {
      "Ú",
      "U"
    },
    {
      "Û",
      "U"
    },
    {
      "Ü",
      "U"
    },
    {
      "ù",
      "u"
    },
    {
      "ú",
      "u"
    },
    {
      "û",
      "u"
    },
    {
      "ü",
      "u"
    },
    {
      "Ý",
      "Y"
    },
    {
      "Ÿ",
      "Y"
    },
    {
      "ý",
      "y"
    },
    {
      "ÿ",
      "y"
    },
    {
      "Ç",
      "C"
    },
    {
      "ç",
      "c"
    },
    {
      "Ñ",
      "N"
    },
    {
      "ñ",
      "n"
    },
    {
      "ß",
      "ss"
    },
    {
      "æ",
      "ae"
    },
    {
      "Æ",
      "AE"
    },
    {
      "œ",
      "oe"
    },
    {
      "Œ",
      "OE"
    }
  }
  for _, pair in ipairs(replacements) do
    s = s:gsub(pair[1], pair[2])
  end
  local out = { }
  for i = 1, #s do
    local b = s:byte(i)
    if b >= 32 and b <= 126 and b ~= 34 and b ~= 92 then
      out[#out + 1] = string.char(b)
    elseif b == 9 or b == 10 or b == 13 or b == 34 or b == 92 then
      out[#out + 1] = " "
    end
  end
  local sanitized = table.concat(out, ""):gsub("%s+", " ")
  return sanitized:match("^%s*(.-)%s*$")
end
local sanitize_id
sanitize_id = function(raw)
  local s = sanitize_ascii(raw):lower()
  s = s:gsub("[^a-z0-9_%-]+", "_")
  s = s:gsub("_+", "_")
  s = s:gsub("^_+", "")
  s = s:gsub("_+$", "")
  s = s:gsub("%-+", "_")
  if #s > 40 then
    s = s:sub(1, 40)
  end
  return s
end
local rule_id = require("filter.rule_id")
local rule_id_base = rule_id.generate
local unique_rule_id
unique_rule_id = function(rule, idx, used)
  local base = rule_id_base(rule, idx)
  local rid = base
  local n = 1
  while used and used[rid] do
    n = n + 1
    rid = tostring(base) .. "_" .. tostring(n)
  end
  if used then
    used[rid] = true
  end
  return rid
end
local read_lines
read_lines = function(filepath)
  local lines = { }
  local f = io.open(filepath, "r")
  if not (f) then
    return lines
  end
  for line in f:lines() do
    line = line:match("^%s*(.-)%s*$")
    if not (line == "" or line:sub(1, 1) == "#") then
      lines[#lines + 1] = line
    end
  end
  f:close()
  return lines
end
local wrap_factory
wrap_factory = function(factory_outer)
  return function(cfg)
    return function(args)
      local factory_inner = factory_outer(cfg)
      local result = factory_inner(args)
      if is_new_style(result) then
        return result
      else
        return {
          capabilities = {
            worker = true,
            nft = false
          },
          eval = result,
          compile_nft = function()
            return nil, "unsupported"
          end
        }
      end
    end
  end
end
local make_plural
make_plural = function(base_factory)
  return function(cfg)
    return function(items)
      if not (type(items) == "table") then
        items = {
          items
        }
      end
      local conds
      do
        local _accum_0 = { }
        local _len_0 = 1
        for _index_0 = 1, #items do
          local item = items[_index_0]
          _accum_0[_len_0] = base_factory(cfg)(item)
          _len_0 = _len_0 + 1
        end
        conds = _accum_0
      end
      local all_nft = #conds > 0
      local requires_auth = false
      for _index_0 = 1, #conds do
        local cond = conds[_index_0]
        local caps = cond.capabilities
        if not (caps and caps.nft) then
          all_nft = false
        end
        if caps and caps.requires_auth then
          requires_auth = true
        end
      end
      local compile_nft_merged = nil
      if all_nft then
        compile_nft_merged = function(family)
          local prefix = nil
          local vals = { }
          local has_failures = false
          for _index_0 = 1, #conds do
            local cond = conds[_index_0]
            local expr, _err = cond.compile_nft(family)
            if expr then
              local p, v = expr:match("^(.+ )([^ ]+)$")
              if not (p) then
                return nil, "unmergeable nft expr: " .. tostring(expr)
              end
              if prefix == nil then
                prefix = p
              elseif prefix ~= p then
                return nil, nil
              end
              vals[#vals + 1] = v
            else
              has_failures = true
            end
          end
          if family == "inet" and has_failures and #vals > 0 then
            return nil, nil
          end
          if #vals == 0 then
            return nil, nil
          end
          if #vals == 1 then
            return tostring(prefix) .. tostring(vals[1]), nil
          else
            return tostring(prefix) .. "{ " .. tostring(table.concat(vals, ', ')) .. " }", nil
          end
        end
      end
      return {
        capabilities = {
          worker = true,
          nft = all_nft,
          nft_dynamic = false,
          requires_auth = requires_auth
        },
        eval = function(req)
          for _index_0 = 1, #conds do
            local cond = conds[_index_0]
            local ok, msg = cond.eval(req)
            if ok then
              return true, msg
            end
          end
          return false, "no match in plural condition"
        end,
        compile_nft = compile_nft_merged
      }
    end
  end
end
local make_from_file
make_from_file = function(base_factory, type_name)
  return function(cfg)
    return function(list_name)
      local lists_dir = (cfg.lists_dir) or (cfg.filter and cfg.filter.lists_dir) or "/etc/custos/lists"
      local filepath = tostring(lists_dir) .. "/" .. tostring(type_name) .. "/" .. tostring(list_name) .. ".txt"
      local items = read_lines(filepath)
      return make_plural(base_factory)(cfg)(items)
    end
  end
end
local make_from_files
make_from_files = function(base_factory, type_name)
  return function(cfg)
    return function(names)
      if not (type(names) == "table") then
        names = {
          names
        }
      end
      local file_factory = make_from_file(base_factory, type_name)(cfg)
      local conds
      do
        local _accum_0 = { }
        local _len_0 = 1
        for _index_0 = 1, #names do
          local name = names[_index_0]
          _accum_0[_len_0] = file_factory(name)
          _len_0 = _len_0 + 1
        end
        conds = _accum_0
      end
      return {
        capabilities = {
          worker = true,
          nft = false,
          nft_dynamic = false
        },
        eval = function(req)
          for _index_0 = 1, #conds do
            local cond = conds[_index_0]
            local ok, msg = cond.eval(req)
            if ok then
              return true, msg
            end
          end
          return false, "no match in any list file"
        end
      }
    end
  end
end
local load_condition
load_condition = function(name)
  local ok, factory_outer = pcall(require, "filter.conditions." .. tostring(name))
  if ok then
    return wrap_factory(factory_outer)
  end
  local base_name = name:match("^(.+)_lists$")
  if base_name then
    local type_name = base_name:match("^[^_]+_(.+)$")
    local base_ok, base_mod = pcall(require, "filter.conditions." .. tostring(base_name))
    if base_ok and type_name then
      return make_from_files((wrap_factory(base_mod)), type_name)
    end
  end
  base_name = name:match("^(.+)_list$")
  if base_name then
    local type_name = base_name:match("^[^_]+_(.+)$")
    local base_ok, base_mod = pcall(require, "filter.conditions." .. tostring(base_name))
    if base_ok and type_name then
      return make_from_file((wrap_factory(base_mod)), type_name)
    end
  end
  base_name = name:match("^(.+)s$")
  if base_name then
    local base_ok, base_mod = pcall(require, "filter.conditions." .. tostring(base_name))
    if base_ok then
      return make_plural((wrap_factory(base_mod)))
    end
  end
  return nil, "Condition '" .. tostring(name) .. "' not found"
end
local load_action
load_action = function(name)
  local ok, factory_outer = pcall(require, "filter.actions." .. tostring(name))
  if not (ok) then
    return nil, factory_outer
  end
  return function(cfg)
    return function(rule)
      local factory_inner = factory_outer(cfg)
      local result = factory_inner(rule)
      if is_new_style(result) then
        return result
      else
        return {
          capabilities = {
            worker = true,
            nft = false
          },
          eval = result,
          compile_nft = function()
            return nil, "unsupported"
          end,
          verdict = function()
            return nil
          end
        }
      end
    end
  end
end
local create_net_condition
create_net_condition = function(prop, net_cidr)
  return {
    capabilities = {
      worker = true,
      nft = true,
      nft_dynamic = false
    },
    prop = prop,
    net_cidr = net_cidr,
    eval = function(req)
      local ip = req[prop]
      if not (ip) then
        return false, "Missing " .. tostring(prop)
      end
      local Net
      Net = require("filter.lib.ipcalc").Net
      local net = Net(net_cidr)
      if not (net) then
        return false, "Invalid CIDR"
      end
      if net:contains(ip) then
        return true, tostring(ip) .. " in " .. tostring(net_cidr)
      else
        return false, tostring(ip) .. " not in " .. tostring(net_cidr)
      end
    end,
    compile_nft = function(family)
      if family == "inet" or family == "ip" then
        return "ip saddr " .. tostring(net_cidr), nil
      end
      if family == "inet6" or family == "ip6" then
        return "ip6 saddr " .. tostring(net_cidr), nil
      end
      return nil, "unsupported family " .. tostring(family)
    end
  }
end
local create_allow_action
create_allow_action = function()
  return {
    capabilities = {
      worker = true,
      nft = true
    },
    eval = function(req)
      return true, "Allowed"
    end,
    compile_nft = function()
      return "accept", nil
    end,
    verdict = function()
      return "accept"
    end
  }
end
local create_deny_action
create_deny_action = function()
  return {
    capabilities = {
      worker = true,
      nft = true
    },
    eval = function(req)
      return false, "Denied"
    end,
    compile_nft = function()
      return "drop", nil
    end,
    verdict = function()
      return "drop"
    end
  }
end
local create_dnsonly_action
create_dnsonly_action = function()
  return {
    capabilities = {
      worker = true,
      nft = false
    },
    eval = function(req)
      return "dnsonly", "DNS only (no nft)"
    end,
    verdict = function()
      return "dnsonly"
    end
  }
end
return {
  is_new_style = is_new_style,
  compute_worker_only = compute_worker_only,
  sanitize_ascii = sanitize_ascii,
  sanitize_id = sanitize_id,
  rule_id_base = rule_id_base,
  unique_rule_id = unique_rule_id,
  load_condition = load_condition,
  load_action = load_action,
  create_net_condition = create_net_condition,
  create_allow_action = create_allow_action,
  create_deny_action = create_deny_action,
  create_dnsonly_action = create_dnsonly_action
}
