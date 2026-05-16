-- src/filter/conditions/to_netlists.moon
-- Condition : l'adresse IP destination appartient à au moins une des netlists.
-- API enrichie : worker-only (multiple netlists complex in nft).

--- @tparam table cfg Configuration
-- @treturn function factory (list_names) → enriched_condition
(cfg) ->
  _to_netlist = require "filter.conditions.to_netlist"
  (list_names) ->
    lists = list_names
    unless type(list_names) == "table"
      lists = { list_names }

    list_conds = {}
    for _, name in ipairs lists
      list_conds[#list_conds + 1] = _to_netlist(cfg)(name)

    {
      capabilities: { worker: true, nft: false, nft_dynamic: false }
      lists: lists
      eval: (req) ->
        for _, list_cond in ipairs list_conds
          ok, msg = list_cond.eval req
          return ok, msg if ok
        false, "#{req.dst_ip or '?'} not in any netlist"
    }
