-- src/filter/conditions/from_vlanlists.moon
-- Condition: VLAN source appartient à une des listes nommées.
-- API enrichie: worker-only (multiple lists complex in nft).

--- @tparam table cfg Configuration
-- @treturn function factory (list_names) → enriched_condition
(cfg) ->
  _from_vlanlist = require "filter.conditions.from_vlanlist"
  (list_names) ->
    lists = list_names
    unless type(list_names) == "table"
      lists = { list_names }
    
    list_conds = {}
    for _, name in ipairs lists
      list_conds[#list_conds + 1] = _from_vlanlist(cfg)(name)
    
    {
      capabilities: { worker: true, nft: false, nft_dynamic: false }
      lists: lists
      eval: (req) ->
        for _, list_cond in ipairs list_conds
          ok, msg = list_cond.eval req
          return ok, msg if ok
        false, "vlan #{req.vlan or '?'} not in any list"
    }
