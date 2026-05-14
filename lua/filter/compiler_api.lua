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
  return not obj.capabilities.nft_static
end
local load_condition
load_condition = function(name)
  local ok, factory_outer = pcall(require, "filter.conditions." .. tostring(name))
  if not (ok) then
    return nil, factory_outer
  end
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
            nft_static = false,
            nft_dynamic = false
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
      nft_static = true,
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
  load_condition = load_condition,
  load_action = load_action,
  create_net_condition = create_net_condition,
  create_allow_action = create_allow_action,
  create_deny_action = create_deny_action,
  create_dnsonly_action = create_dnsonly_action
}
