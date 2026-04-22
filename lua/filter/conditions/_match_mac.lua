return function(prop)
  return function(cfg)
    return function(mac_or_alias)
      local mac_map = cfg.macs or { }
      local target_mac = nil
      if mac_or_alias and mac_or_alias ~= "_any" and mac_or_alias ~= "_none" then
        target_mac = (mac_map[mac_or_alias] or mac_or_alias):lower()
      end
      return function(req)
        local _mac = req[prop]
        if mac_or_alias == "_any" then
          return _mac ~= nil, "MAC available"
        end
        if mac_or_alias == "_none" then
          return _mac == nil, "MAC not available"
        end
        if not (_mac) then
          return false, "MAC not available in request"
        end
        return _mac:lower() == target_mac, "MAC " .. tostring(_mac) .. " vs " .. tostring(target_mac) .. " (" .. tostring(mac_or_alias) .. ")"
      end
    end
  end
end
