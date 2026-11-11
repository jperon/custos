local Net
Net = require("filter.lib.ipcalc").Net
local compiler_api = require("filter.compiler_api")
local log = require("log")
local build_cidr_condition
build_cidr_condition = function(opts)
  local prop, nft_dir, net_cidr
  prop, nft_dir, net_cidr = opts.prop, opts.nft_dir, opts.net_cidr
  local subject = opts.subject or ""
  local _net = Net(net_cidr)
  if not (_net) then
    return {
      capabilities = {
        worker = true,
        nft = false,
        nft_dynamic = false
      },
      net_cidr = net_cidr,
      eval = function(req)
        return false, "Invalid CIDR: " .. tostring(net_cidr)
      end
    }
  end
  return {
    capabilities = {
      worker = true,
      nft = true,
      nft_dynamic = false
    },
    net_cidr = net_cidr,
    _net = _net,
    eval = function(req)
      local ip = req[prop]
      if not (ip) then
        return false, "Missing " .. tostring(prop)
      end
      if _net:contains(ip) then
        return true, tostring(ip) .. " in " .. tostring(subject) .. tostring(net_cidr)
      else
        return false, tostring(ip) .. " not in " .. tostring(subject) .. tostring(net_cidr)
      end
    end,
    compile_nft = function(family)
      if net_cidr:find(":") then
        if family == "inet6" or family == "ip6" then
          return "ip6 " .. tostring(nft_dir) .. " " .. tostring(net_cidr), nil
        end
        return nil, "IPv6 CIDR in IPv4 family"
      else
        if family == "inet" or family == "ip" then
          return "ip " .. tostring(nft_dir) .. " " .. tostring(net_cidr), nil
        end
        return nil, "IPv4 CIDR in IPv6 family"
      end
    end
  }
end
local net_alias_cidrs
net_alias_cidrs = function(value)
  if value == nil then
    return { }
  end
  if type(value) == "string" then
    return {
      value
    }
  end
  if type(value) == "table" then
    return value
  end
  return { }
end
local build_alias_condition
build_alias_condition = function(cfg, opts, group)
  local cidrs = net_alias_cidrs(group)
  local base_factory
  base_factory = function(c)
    return function(item)
      return build_cidr_condition({
        prop = opts.prop,
        nft_dir = opts.nft_dir,
        subject = opts.subject,
        net_cidr = item
      })
    end
  end
  local cond = compiler_api.make_plural(base_factory)(cfg)(cidrs)
  if #cidrs > 1 then
    cond.capabilities = {
      worker = true,
      nft = false,
      nft_dynamic = false
    }
    cond.compile_nft = function()
      return nil, "multi-CIDR alias is worker-only"
    end
  end
  return cond
end
local build_net_arg_condition
build_net_arg_condition = function(cfg, opts)
  local net_cidr = opts.net_cidr
  local is_literal = type(net_cidr) == "string" and (Net(net_cidr)) ~= nil
  local special = net_cidr == "_any" or net_cidr == "_none"
  if type(net_cidr) == "string" and not is_literal and not special then
    local nets = (cfg and cfg.nets) or { }
    local group = nets[net_cidr]
    if group ~= nil then
      local cond = build_alias_condition(cfg, opts, group)
      cond.net_alias = net_cidr
      return cond
    end
    local warn = log.log_warn
    if warn then
      warn(function()
        return {
          action = "filter_net_unknown",
          condition = opts.cond_name or "net",
          net = net_cidr
        }
      end)
    end
  end
  return build_cidr_condition(opts)
end
return {
  build_cidr_condition = build_cidr_condition,
  build_net_arg_condition = build_net_arg_condition
}
