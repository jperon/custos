return function(cfg)
  return function(list_names)
    local lists = list_names
    if not (type(list_names) == "table") then
      lists = {
        list_names
      }
    end
    return {
      capabilities = {
        worker = true,
        nft_static = false,
        nft_dynamic = false
      },
      lists = lists,
      eval = function(req)
        local ip = req.src_ip
        if not (ip) then
          return false, "src_ip not available"
        end
        local Net
        Net = require("filter.lib.ipcalc").Net
        for _, list_name in ipairs(lists) do
          local nets = cfg.nets and cfg.nets[list_name] or { }
          for _, cidr in ipairs(nets) do
            local net = Net(cidr)
            if net and net:contains(ip) then
              return true, tostring(ip) .. " in " .. tostring(cidr) .. " (" .. tostring(list_name) .. ")"
            end
          end
        end
        return false, tostring(ip) .. " not in any netlist"
      end
    }
  end
end
