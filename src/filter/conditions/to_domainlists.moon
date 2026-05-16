-- src/filter/conditions/to_domainlists.moon
-- Condition : le domaine appartient à au moins une des listes nommées.
-- API enrichie : worker-only (DNS matching).

--- @tparam table cfg Configuration
-- @treturn function factory (listnames) → enriched_condition
(cfg) ->
  to_domainlist_factory = require "filter.conditions.to_domainlist"
  (listnames) ->
    lists = listnames
    unless type(listnames) == "table"
      lists = { listnames }
    
    list_conds = {}
    for _, name in ipairs lists
      list_conds[#list_conds + 1] = to_domainlist_factory(cfg)(name)
      
    {
      capabilities: { worker: true, nft: false, nft_dynamic: false }
      lists: lists
      eval: (req) ->
        for _, list_cond in ipairs list_conds
          ok, msg = list_cond.eval req
          return ok, msg if ok
        false, "Domain not in any of: #{table.concat lists, ', '}"
      creates_dynamic_scope: true
    }
