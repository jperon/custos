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
        local _mac = req.mac
        if not (_mac) then
          return false, "mac not available"
        end
        local _mac_lower = _mac:lower()
        for _, list_name in ipairs(lists) do
          local macs = cfg.macs and cfg.macs[list_name] or { }
          for _, mac in ipairs(macs) do
            if _mac_lower == mac:lower() then
              return true, "mac " .. tostring(_mac) .. " in " .. tostring(list_name)
            end
          end
        end
        return false, "mac " .. tostring(_mac) .. " not in any list"
      end
    }
  end
end
