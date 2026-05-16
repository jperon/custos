return function(cfg)
  return function(list_name)
    local raw_macs = cfg.macs and cfg.macs[list_name] or { }
    local macs_lower
    do
      local _accum_0 = { }
      local _len_0 = 1
      for _index_0 = 1, #raw_macs do
        local mac = raw_macs[_index_0]
        _accum_0[_len_0] = mac:lower()
        _len_0 = _len_0 + 1
      end
      macs_lower = _accum_0
    end
    return {
      capabilities = {
        worker = true,
        nft_static = true,
        nft_dynamic = false
      },
      list_name = list_name,
      macs = raw_macs,
      eval = function(req)
        local _mac = req.mac
        if not (_mac) then
          return false, "mac not available"
        end
        local _mac_lower = _mac:lower()
        for _, mac in ipairs(macs_lower) do
          if _mac_lower == mac then
            return true, "mac " .. tostring(_mac) .. " in " .. tostring(list_name)
          end
        end
        return false, "mac " .. tostring(_mac) .. " not in " .. tostring(list_name)
      end,
      compile_nft = function(family)
        local set_name = "macs_" .. tostring(list_name)
        return "ether saddr @" .. tostring(set_name), nil
      end
    }
  end
end
