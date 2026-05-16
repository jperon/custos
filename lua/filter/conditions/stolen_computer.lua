return function(cfg)
  return function(macs)
    if not (type(macs) == "table") then
      return {
        capabilities = {
          worker = true,
          nft_static = false,
          nft_dynamic = false
        },
        eval = function(req)
          return false, "stolen_computer requires a table of MACs"
        end
      }
    end
    local blacklist = { }
    local macs_lower = { }
    for _index_0 = 1, #macs do
      local mac = macs[_index_0]
      local mac_lower = mac:lower()
      blacklist[mac_lower] = true
      macs_lower[#macs_lower + 1] = mac_lower
    end
    return {
      capabilities = {
        worker = true,
        nft_static = true,
        nft_dynamic = false
      },
      macs = macs,
      eval = function(req)
        local _mac = req.mac
        if not (_mac) then
          return false, "MAC not available"
        end
        if blacklist[_mac:lower()] then
          return true, "Stolen computer: " .. tostring(_mac)
        else
          return false, "MAC " .. tostring(_mac) .. " not in blacklist"
        end
      end,
      compile_nft = function(family)
        local mac_str = table.concat(macs_lower, ", ")
        return "ether saddr { " .. tostring(mac_str) .. " }", nil
      end
    }
  end
end
