-- src/filter/conditions/from_vlanlist.moon
-- Condition: VLAN source appartient à une liste nommée.
-- API enrichie: support sets nft pour les listes de VLANs.

--- @tparam table cfg Configuration
-- @treturn function factory (list_name) → enriched_condition
(cfg) ->
  (list_name) ->
    vlans = cfg.vlans and cfg.vlans[list_name] or {}
    
    -- Pré-construire un set pour lookup O(1)
    vlan_set = {}
    for _, v in ipairs vlans
      vlan_set[v] = true
    
    {
      capabilities: { worker: true, nft: true, nft_dynamic: false }
      list_name: list_name
      vlans: vlans
      eval: (req) ->
        _val = req.vlan
        return false, "vlan not available" unless _val
        if vlan_set[_val]
          return true, "vlan #{_val} in #{list_name}"
        false, "vlan #{_val} not in #{list_name}"
      compile_nft: (family) ->
        set_name = "vlans_#{list_name}"
        return "vlan id @#{set_name}", nil
    }
