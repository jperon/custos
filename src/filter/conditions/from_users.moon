-- src/filter/conditions/from_users.moon
-- Condition : l'IP source a une session active pour l'un des utilisateurs listés.
-- API enrichie: worker-only (dynamic session lookup).

--- @tparam table cfg Configuration
-- @treturn function factory (users) → enriched_condition
(cfg) ->
  _from_user_factory = require "filter.conditions.from_user"
  (users) ->
    user_list = users
    unless type(users) == "table"
      user_list = { users }
    
    user_conds = {}
    for _, user in ipairs user_list
      user_conds[#user_conds + 1] = _from_user_factory(cfg)(user)
      
    {
      capabilities: { worker: true, nft_static: false, nft_dynamic: false }
      user_list: user_list
      eval: (req) ->
        for _, user_cond in ipairs user_conds
          ok, msg = user_cond.eval req
          return ok, msg if ok
        false, "Not matched by any user"
    }
