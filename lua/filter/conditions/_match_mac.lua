return function(prop)
  return function(cfg)
    return function(mac)
      mac = mac:lower()
      return function(req)
        local _mac = req[prop]
        if not (_mac) then
          return false, "MAC not available in request"
        end
        return _mac:lower() == mac, "MAC " .. tostring(_mac) .. " vs " .. tostring(mac)
      end
    end
  end
end
