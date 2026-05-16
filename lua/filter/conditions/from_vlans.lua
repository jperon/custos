return function(cfg)
  return function(vlan_list)
    if not (type(vlan_list) == "table") then
      return {
        capabilities = {
          worker = true,
          nft = false,
          nft_dynamic = false
        }
      }
    end
    return {
      capabilities = {
        worker = true,
        nft = true,
        nft_dynamic = false
      },
      vlan_list = vlan_list,
      eval = function(req)
        local _val = req.vlan
        if not (_val) then
          return false, "vlan not available"
        end
        for _, v in ipairs(vlan_list) do
          if v == _val then
            return true, "vlan " .. tostring(_val) .. " matched"
          end
        end
        return false, "vlan " .. tostring(_val) .. " not in list"
      end,
      compile_nft = function(family)
        local vlan_str = table.concat((function()
          local _accum_0 = { }
          local _len_0 = 1
          for _index_0 = 1, #vlan_list do
            local v = vlan_list[_index_0]
            _accum_0[_len_0] = tostring(v)
            _len_0 = _len_0 + 1
          end
          return _accum_0
        end)(), ", ")
        return "vlan id { " .. tostring(vlan_str) .. " }", nil
      end
    }
  end
end
