-- src/filter/conditions/from_userlist.moon
-- Condition : l'IP source a une session active pour un utilisateur
-- appartenant au groupe nommé (cfg.userlists[name]).
-- Analogue de from_netlist / from_maclist pour les utilisateurs.

{ :log_debug } = require "log"

--- @tparam table cfg Configuration du filtre (cfg.userlists: table de listes d'utilisateurs)
-- @treturn function factory (name: string) → (req) → bool, reason
(cfg) -> (name) ->
  _from_user = (require "filter.conditions.from_user") cfg
  userlists_cfg  = cfg.userlists or {}
  sessions_file = (cfg.auth and cfg.auth.sessions_file) or "unknown"

  --- @tparam table req {src_ip: string, ...}
  -- @treturn boolean, string
  (req) ->
    userlist = userlists_cfg[name]
    if not userlist and req.user and req.user ~= "unknown"
      log_debug {
        action: "from_userlist_missing"
        list: name
        hinted_user: req.user
        src_ip: req.src_ip or ""
        sessions_file: sessions_file
      }
    return false, "User list '#{name}' not defined" unless userlist
    last_reason = nil
    for user in *userlist
      ok, reason = (_from_user user)(req)
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
