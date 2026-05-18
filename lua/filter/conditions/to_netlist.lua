return function(cfg)
  local Net
  Net = require("filter.lib.ipcalc").Net
  return function(list_name)
    local raw_nets = cfg.nets and cfg.nets[list_name] or cfg.netlists and cfg.netlists[list_name] or (cfg.filter and cfg.filter.netlists and cfg.filter.netlists[list_name]) or { }
    if type(raw_nets) == "string" then
      raw_nets = {
        raw_nets
      }
    end
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
        local ip = req.dst_ip
        if not (ip) then
          return false, "dst_ip not available"
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
        if family == "ip6" then
          return "ip6 daddr @" .. tostring(set_name) .. "6", nil
        else
          return "ip daddr @" .. tostring(set_name), nil
        end
      end
    }
  end
end
