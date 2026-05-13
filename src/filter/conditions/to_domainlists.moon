-- src/filter/conditions/to_domainlists.moon
-- Condition : le domaine appartient à au moins une des listes nommées.
-- API enrichie : worker-only (DNS matching).

--- @tparam table cfg Configuration
-- @treturn function factory (listnames) → enriched_condition
(cfg) ->
  (listnames) ->
    lists = listnames
    unless type(listnames) == "table"
      lists = { listnames }
    
    {
      capabilities: { worker: true, nft_static: false, nft_dynamic: false }
      worker_only: true
      lists: lists
      eval: (req) ->
        to_domainlist_factory = require "filter.conditions.to_domainlist"
        for _, name in ipairs lists
          list_cond = to_domainlist_factory(cfg)(name)
          ok, msg = list_cond.eval req
          return ok, msg if ok
        false, "Domain not in any of: #{table.concat lists, ', '}"
      compile_nft: -> nil, "to_domainlists requires worker (DNS lookup)"
      creates_dynamic_scope: true
    }
