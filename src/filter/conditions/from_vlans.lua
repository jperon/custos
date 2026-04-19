return function(cfg)
  return function(val)
    if not (type(val == "table")) then
      error("from_vlans requires a table of integers")
    end
    return function(req)
      local _val = req.vlan
      if not (_val) then
        return false, "vlan not available in request"
      end
      for _, v in ipairs(val) do
        if v == _val then
          return true, nil
        end
      end
      return false, "vlan " .. tostring(_val) .. " not in list"
    end
  end
end
