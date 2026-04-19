return function(prop)
  return function(cfg)
    return function(val)
      return function(req)
        local _val = req[prop]
        if not (_val) then
          return false, tostring(prop) .. " not available in request"
        end
        return _val == val, tostring(prop) .. " " .. tostring(_val) .. " vs " .. tostring(val)
      end
    end
  end
end
