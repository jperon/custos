return function(prop)
  return function(cfg)
    return function(mac_or_alias)
      local mac_map = cfg.macs or { }
      local target_mac = mac_map[mac_or_alias] or mac_or_alias
      target_mac = target_mac:lower()
      return function(req)
        local _mac = req[prop]
        if not (_mac) then
          return false, "MAC not available in request"
        end
        return _mac:lower() == target_mac, "MAC " .. tostring(_mac) .. " vs " .. tostring(target_mac) .. " (" .. tostring(mac_or_alias) .. ")"
      end
    end
  end
end
