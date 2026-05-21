local _schema = {
  label = "VLAN source",
  description = "Requête arrivant sur un VLAN ID spécifique (support nft natif)",
  category = "source",
  arg_type = "integer",
  arg_hint = "ex: 100"
}
local _factory
_factory = function(cfg)
  return function(vlan_id)
    return {
      capabilities = {
        worker = true,
        nft = true,
        nft_dynamic = false
      },
      vlan_id = vlan_id,
      eval = function(req)
        local _val = req.vlan
        if vlan_id == "_any" then
          return _val ~= nil, "vlan is present"
        end
        if vlan_id == "_none" then
          return _val == nil, "vlan is absent"
        end
        if not (_val) then
          return false, "vlan not available"
        end
        return _val == vlan_id, "vlan " .. tostring(_val) .. " vs " .. tostring(vlan_id)
      end,
      compile_nft = function(family)
        if vlan_id == "_any" or vlan_id == "_none" then
          return nil, "vlan _any/_none not supported in nft"
        end
        return "vlan id " .. tostring(vlan_id), nil
      end
    }
  end
end
return {
  schema = _schema,
  factory = _factory
}
