local Net
Net = require("filter.lib.ipcalc").Net
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
return {
  build_cidr_condition = build_cidr_condition
}
