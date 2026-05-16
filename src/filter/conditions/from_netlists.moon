-- src/filter/conditions/from_netlists.moon
-- Condition : l'adresse IP source appartient à au moins une des netlists.
-- API enrichie : worker-only (multiple netlists complex in nft).

--- @tparam table cfg Configuration
-- @treturn function factory (list_names) → enriched_condition
(cfg) ->
  _from_netlist = require "filter.conditions.from_netlist"
  (list_names) ->
    lists = list_names
    unless type(list_names) == "table"
      lists = { list_names }
    
    list_conds = {}
    for _, name in ipairs lists
      list_conds[#list_conds + 1] = _from_netlist(cfg)(name)
    
    {
      capabilities: { worker: true, nft_static: false, nft_dynamic: false }
      lists: lists
      eval: (req) ->
        for _, list_cond in ipairs list_conds
          ok, msg = list_cond.eval req
          return ok, msg if ok
        false, "#{req.src_ip or '?'} not in any netlist"
    }
