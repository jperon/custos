return function(prop)
  return function(cfg)
    return function(list_name)
      return function(req)
        local _val = req[prop]
        if not (_val) then
          return false, tostring(prop) .. " not available in request"
        end
        local target_list = cfg.lists and cfg.lists[list_name] or { }
        for _, v in ipairs(target_list) do
          if v == _val then
            return true, nil
          end
        end
        return false, tostring(prop) .. " " .. tostring(_val) .. " not in list " .. tostring(list_name)
      end
    end
  end
end
