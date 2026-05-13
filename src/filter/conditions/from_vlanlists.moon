-- src/filter/conditions/from_vlanlists.moon
-- Condition: VLAN source appartient à une des listes nommées.
-- API enrichie: worker-only (multiple lists complex in nft).

--- @tparam table cfg Configuration
-- @treturn function factory (list_names) → enriched_condition
(cfg) ->
  (list_names) ->
    lists = list_names
    unless type(list_names) == "table"
      lists = { list_names }
    
    {
      capabilities: { worker: true, nft_static: false, nft_dynamic: false }
      lists: lists
      eval: (req) ->
        _val = req.vlan
        return false, "vlan not available" unless _val
        for _, list_name in ipairs lists
          vlans = cfg.vlans and cfg.vlans[list_name] or {}
          for _, v in ipairs vlans
            return true, "vlan #{_val} in #{list_name}" if v == _val
        false, "vlan #{_val} not in any list"
    }
