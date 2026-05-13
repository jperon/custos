-- src/filter/conditions/from_users.moon
-- Condition : l'IP source a une session active pour l'un des utilisateurs listés.
-- API enrichie: worker-only (dynamic session lookup).

--- @tparam table cfg Configuration
-- @treturn function factory (users) → enriched_condition
(cfg) ->
  (users) ->
    user_list = users
    unless type(users) == "table"
      user_list = { users }
    
    {
      capabilities: { worker: true, nft_static: false, nft_dynamic: false }
      worker_only: true
      user_list: user_list
      eval: (req) ->
        _from_user = require "filter.conditions.from_user"
        for _, user in ipairs user_list
          user_cond = (_from_user cfg)(user)
          ok, msg = user_cond.eval req
          return ok, msg if ok
        false, "Not matched by any user"
      compile_nft: -> nil, "from_users requires worker (dynamic sessions)"
      creates_dynamic_scope: false
    }
