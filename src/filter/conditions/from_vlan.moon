-- src/filter/conditions/from_vlan.moon
-- Condition : match sur le VLAN ID source.
-- API enrichie : support worker + nft.

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (vlan_id) → enriched_condition
(cfg) ->
  (vlan_id) ->
    {
      capabilities: { worker: true, nft_static: true, nft_dynamic: false }
      vlan_id: vlan_id
      eval: (req) ->
        _val = req.vlan
        if vlan_id == "_any"
          return _val ~= nil, "vlan is present"
        if vlan_id == "_none"
          return _val == nil, "vlan is absent"
        return false, "vlan not available" unless _val
        _val == vlan_id, "vlan #{_val} vs #{vlan_id}"
      compile_nft: (family) ->
        if vlan_id == "_any" or vlan_id == "_none"
          return nil, "vlan _any/_none not supported in nft"
        return "vlan id #{vlan_id}", nil
    }
