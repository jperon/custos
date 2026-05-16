-- src/filter/conditions/from_userlists.moon
-- Condition : l'IP source a une session active pour un utilisateur
-- appartenant à au moins un des groupes nommés (cfg.userlists).
-- API enrichie: worker-only (dynamic session lookup).

{ :log_debug } = require "log"

--- @tparam table cfg Configuration
-- @treturn function factory (names) → enriched_condition
(cfg) ->
  _from_userlist_factory = require "filter.conditions.from_userlist"
  (names) ->
    list_names = names
    unless type(names) == "table"
      list_names = { names }
    
    list_conds = {}
    for _, name in ipairs list_names
      list_conds[#list_conds + 1] = _from_userlist_factory(cfg)(name)
    
    {
      capabilities: { worker: true, nft_static: false, nft_dynamic: false }
      list_names: list_names
      eval: (req) ->
        last_reason = nil
        for _, list_cond in ipairs list_conds
          ok, reason = list_cond.eval req
          return true, "In one of: #{table.concat list_names, ', '}" if ok
          last_reason = reason
        if req.user and req.user ~= "unknown"
          log_debug {
            action: "from_userlists_no_match"
            hinted_user: req.user
            src_ip: req.src_ip or ""
            lists: table.concat list_names, ","
            last_reason: last_reason or ""
          }
        false, "Not in any of: #{table.concat list_names, ', '}"
    }
