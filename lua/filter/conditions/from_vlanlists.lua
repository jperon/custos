return function(cfg)
  return function(list_names)
    local lists = list_names
    if not (type(list_names) == "table") then
      lists = {
        list_names
      }
    end
    return {
      capabilities = {
        worker = true,
        nft_static = false,
        nft_dynamic = false
      },
      lists = lists,
      eval = function(req)
        local _val = req.vlan
        if not (_val) then
          return false, "vlan not available"
        end
        for _, list_name in ipairs(lists) do
          local vlans = cfg.vlans and cfg.vlans[list_name] or { }
          for _, v in ipairs(vlans) do
            if v == _val then
              return true, "vlan " .. tostring(_val) .. " in " .. tostring(list_name)
            end
          end
        end
        return false, "vlan " .. tostring(_val) .. " not in any list"
      end
    }
  end
end
