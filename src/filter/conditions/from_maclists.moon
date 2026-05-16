-- src/filter/conditions/from_maclists.moon
-- Condition : l'adresse MAC source appartient à l'une des listes nommées (cfg.macs).
-- API enrichie : worker-only (multiple lists complex in nft).

--- @tparam table cfg Configuration
-- @treturn function factory (list_names) → enriched_condition
(cfg) ->
  _from_maclist = require "filter.conditions.from_maclist"
  (list_names) ->
    lists = list_names
    unless type(list_names) == "table"
      lists = { list_names }
    
    list_conds = {}
    for _, name in ipairs lists
      list_conds[#list_conds + 1] = _from_maclist(cfg)(name)
    
    {
      capabilities: { worker: true, nft_static: false, nft_dynamic: false }
      lists: lists
      eval: (req) ->
        for _, list_cond in ipairs list_conds
          ok, msg = list_cond.eval req
          return ok, msg if ok
        false, "mac #{req.mac or '?'} not in any list"
    }
