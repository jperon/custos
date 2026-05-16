return function(cfg)
  local Net
  Net = require("filter.lib.ipcalc").Net
  return function(list_name)
    local raw_nets = cfg.nets and cfg.nets[list_name] or { }
    local compiled = { }
    for _, cidr in ipairs(raw_nets) do
      local net = Net(cidr)
      if net then
        compiled[#compiled + 1] = {
          net = net,
          cidr = cidr
        }
      end
    end
    return {
      capabilities = {
        worker = true,
        nft = true,
        nft_dynamic = false
      },
      list_name = list_name,
      nets = raw_nets,
      eval = function(req)
        local ip = req.src_ip
        if not (ip) then
          return false, "src_ip not available"
        end
        for _, entry in ipairs(compiled) do
          if entry.net:contains(ip) then
            return true, tostring(ip) .. " in " .. tostring(entry.cidr) .. " (" .. tostring(list_name) .. ")"
          end
        end
        return false, tostring(ip) .. " not in " .. tostring(list_name)
      end,
      compile_nft = function(family)
        local set_name = "nets_" .. tostring(list_name)
        local is_ipv6 = raw_nets[1] and raw_nets[1]:find(":")
        if is_ipv6 then
          return "ip6 saddr @" .. tostring(set_name), nil
        else
          return "ip saddr @" .. tostring(set_name), nil
        end
      end
    }
  end
end
