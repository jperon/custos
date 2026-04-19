-- src/filter/conditions/from_userlists.moon
-- Condition : l'IP source a une session active pour un utilisateur
-- appartenant à au moins un des groupes nommés (cfg.userlists).
-- Analogue de from_netlists / from_maclists pour les utilisateurs.

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (names: table) → (req) → bool, reason
(cfg) -> (names) ->
  _from_userlist = (require "filter.conditions.from_userlist") cfg

  --- @tparam table req {src_ip: string, ...}
  -- @treturn boolean, string
  (req) ->
    for _, name in ipairs names
      ok = (_from_userlist name)(req)
      return true, "In one of: #{table.concat names, ', '}" if ok
    false, "Not in any of: #{table.concat names, ', '}"
