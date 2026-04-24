local stolen_computer
stolen_computer = function(cfg)
  return function(macs)
    local blacklist = { }
    for _index_0 = 1, #macs do
      local mac = macs[_index_0]
      blacklist[mac:lower()] = true
    end
    return function(req)
      local _mac = req.mac
      if not (_mac) then
        return false, "MAC not available"
      end
      if blacklist[_mac:lower()] then
        return true, "Stolen computer: " .. tostring(_mac)
      else
        return false, "MAC " .. tostring(_mac) .. " not in blacklist"
      end
    end
  end
end
return stolen_computer
