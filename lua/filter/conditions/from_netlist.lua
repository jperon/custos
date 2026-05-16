return function(cfg)
  return function(list_name)
    local nets = cfg.nets and cfg.nets[list_name] or { }
    return {
      capabilities = {
        worker = true,
        nft_static = true,
        nft_dynamic = false
      },
      list_name = list_name,
      nets = nets,
      eval = function(req)
        local ip = req.src_ip
        if not (ip) then
          return false, "src_ip not available"
        end
        local Net
        Net = require("filter.lib.ipcalc").Net
        for _, cidr in ipairs(nets) do
          local net = Net(cidr)
          if net and net:contains(ip) then
            return true, tostring(ip) .. " in " .. tostring(cidr) .. " (" .. tostring(list_name) .. ")"
          end
        end
        return false, tostring(ip) .. " not in " .. tostring(list_name)
      end,
      compile_nft = function(family)
        local set_name = "nets_" .. tostring(list_name)
        local is_ipv6 = nets[1] and nets[1]:find(":")
        if is_ipv6 then
          return "ip6 saddr @" .. tostring(set_name), nil
        else
          return "ip saddr @" .. tostring(set_name), nil
        end
      end
    }
  end
end
