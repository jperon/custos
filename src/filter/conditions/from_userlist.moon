-- src/filter/conditions/from_userlist.moon
-- Condition : l'IP source a une session active pour un utilisateur
-- appartenant au groupe nommé (cfg.userlists[name]).
-- API enrichie: worker-only (dynamic session lookup).

{ :log_debug } = require "log"

--- @tparam table cfg Configuration
-- @treturn function factory (name) → enriched_condition
(cfg) ->
  _from_user_factory = require "filter.conditions.from_user"
  (name) ->
    userlists_cfg = cfg.userlists or {}
    sessions_file = (cfg.auth and cfg.auth.sessions_file) or "unknown"
    userlist = userlists_cfg[name]
    
    unless userlist
      return {
        capabilities: { worker: true, nft_static: false, nft_dynamic: false }
        eval: (req) ->
          if req.user and req.user ~= "unknown"
            log_debug {
              action: "from_userlist_missing"
              list: name
              hinted_user: req.user
              src_ip: req.src_ip or ""
              sessions_file: sessions_file
            }
          false, "User list '#{name}' not defined"
      }
    
    user_conds = {}
    for user in *userlist
      user_conds[#user_conds + 1] = _from_user_factory(cfg)(user)
      
    {
      capabilities: { worker: true, nft_static: false, nft_dynamic: false }
      name: name
      userlist: userlist
      eval: (req) ->
        last_reason = nil
        for _, user_cond in ipairs user_conds
          ok, reason = user_cond.eval req
          return true, "#{req.src_ip} in userlist '#{name}'" if ok
          last_reason = reason
        if req.user and req.user ~= "unknown"
          log_debug {
            action: "from_userlist_no_match"
            list: name
            hinted_user: req.user
            src_ip: req.src_ip or ""
            list_size: #userlist
            sessions_file: sessions_file
            last_reason: last_reason or ""
          }
        false, "Not in userlist '#{name}'"
    }
