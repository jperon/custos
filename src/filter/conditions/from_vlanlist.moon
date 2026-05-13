-- src/filter/conditions/from_vlanlist.moon
-- Condition: VLAN source appartient à une liste nommée.
-- API enrichie: support sets nft pour les listes de VLANs.

--- @tparam table cfg Configuration
-- @treturn function factory (list_name) → enriched_condition
(cfg) ->
  (list_name) ->
    vlans = cfg.vlans and cfg.vlans[list_name] or {}
    
    {
      capabilities: { worker: true, nft_static: true, nft_dynamic: false }
      list_name: list_name
      vlans: vlans
      eval: (req) ->
        _val = req.vlan
        return false, "vlan not available" unless _val
        for _, v in ipairs vlans
          return true, "vlan #{_val} in #{list_name}" if v == _val
        false, "vlan #{_val} not in #{list_name}"
      compile_nft: (family) ->
        -- Build set name for this vlan list
        set_name = "vlans_#{list_name}"
        return "vlan id @#{set_name}", nil
    }
