-- src/filter/conditions/from_userlist.moon
-- Condition : l'IP source a une session active pour un utilisateur
-- appartenant au groupe nommé (cfg.userlists[name]).
-- API enrichie: worker-only (dynamic session lookup).

{ :log_debug } = require "log"

--- @tparam table cfg Configuration
-- @treturn function factory (name) → enriched_condition
(cfg) ->
  (name) ->
    userlists_cfg = cfg.userlists or {}
    sessions_file = (cfg.auth and cfg.auth.sessions_file) or "unknown"
    userlist = userlists_cfg[name]
    
    unless userlist
      return {
        capabilities: { worker: true, nft_static: false, nft_dynamic: false }
        worker_only: true
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
        compile_nft: -> nil, "undefined userlist"
        creates_dynamic_scope: false
      }
    
    {
      capabilities: { worker: true, nft_static: false, nft_dynamic: false }
      worker_only: true
      name: name
      userlist: userlist
      eval: (req) ->
        _from_user = (require "filter.conditions.from_user") cfg
        last_reason = nil
        for user in *userlist
          user_cond = _from_user(user)
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
      compile_nft: -> nil, "from_userlist requires worker (dynamic sessions)"
      creates_dynamic_scope: false
    }
