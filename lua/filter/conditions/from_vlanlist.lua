return function(cfg)
  return function(list_name)
    local vlans = cfg.vlans and cfg.vlans[list_name] or { }
    local vlan_set = { }
    for _, v in ipairs(vlans) do
      vlan_set[v] = true
    end
    return {
      capabilities = {
        worker = true,
        nft_static = true,
        nft_dynamic = false
      },
      list_name = list_name,
      vlans = vlans,
      eval = function(req)
        local _val = req.vlan
        if not (_val) then
          return false, "vlan not available"
        end
        if vlan_set[_val] then
          return true, "vlan " .. tostring(_val) .. " in " .. tostring(list_name)
        end
        return false, "vlan " .. tostring(_val) .. " not in " .. tostring(list_name)
      end,
      compile_nft = function(family)
        local set_name = "vlans_" .. tostring(list_name)
        return "vlan id @" .. tostring(set_name), nil
      end
    }
  end
end
