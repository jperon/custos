-- src/filter/conditions/from_userlist.moon
-- Condition : l'IP source a une session active pour un utilisateur
-- appartenant au groupe nommé (cfg.userlists[name]).
-- Analogue de from_netlist / from_maclist pour les utilisateurs.

--- @tparam table cfg Configuration du filtre (cfg.userlists: table de listes d'utilisateurs)
-- @treturn function factory (name: string) → (req) → bool, reason
(cfg) -> (name) ->
  _from_user = (require "filter.conditions.from_user") cfg
  userlists_cfg  = cfg.userlists or {}

  --- @tparam table req {src_ip: string, ...}
  -- @treturn boolean, string
  (req) ->
    userlist = userlists_cfg[name]
    return false, "User list '#{name}' not defined" unless userlist
    for user in *userlist
      ok = (_from_user user)(req)
      return true, "#{req.src_ip} in userlist '#{name}'" if ok
    false, "Not in userlist '#{name}'"
