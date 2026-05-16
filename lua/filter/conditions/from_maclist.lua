return function(cfg)
  return function(list_name)
    local macs = cfg.macs and cfg.macs[list_name] or { }
    return {
      capabilities = {
        worker = true,
        nft_static = true,
        nft_dynamic = false
      },
      list_name = list_name,
      macs = macs,
      eval = function(req)
        local _mac = req.mac
        if not (_mac) then
          return false, "mac not available"
        end
        local _mac_lower = _mac:lower()
        for _, mac in ipairs(macs) do
          if _mac_lower == mac:lower() then
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
