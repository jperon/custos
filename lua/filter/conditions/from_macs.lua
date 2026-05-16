return function(cfg)
  return function(macs)
    if not (type(macs) == "table") then
      return {
        capabilities = {
          worker = true,
          nft = false,
          nft_dynamic = false
        },
        eval = function(req)
          return false, "from_macs requires a table of MACs"
        end
      }
    end
    local macs_lower
    do
      local _accum_0 = { }
      local _len_0 = 1
      for _index_0 = 1, #macs do
        local mac = macs[_index_0]
        _accum_0[_len_0] = mac:lower()
        _len_0 = _len_0 + 1
      end
      macs_lower = _accum_0
    end
    return {
      capabilities = {
        worker = true,
        nft = true,
        nft_dynamic = false
      },
      macs = macs,
      eval = function(req)
        local _mac = req.mac
        if not (_mac) then
          return false, "mac not available"
        end
        local _mac_lower = _mac:lower()
        for _, mac in ipairs(macs_lower) do
          if _mac_lower == mac then
            return true, "mac " .. tostring(_mac) .. " matched"
          end
        end
        return false, "mac " .. tostring(_mac) .. " not in list"
      end,
      compile_nft = function(family)
        local mac_str = table.concat(macs_lower, ", ")
        return "ether saddr { " .. tostring(mac_str) .. " }", nil
      end
    }
  end
end
