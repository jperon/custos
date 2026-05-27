-- src/auth/rule_user.moon
-- Vérifie si un utilisateur authentifié qualifie pour une règle de filtre.
--
-- Utilisé par auth/server.moon (login, logout) pour décider quels sets nft
-- per-rule doivent être peuplés / vidés pour cet utilisateur.
--
-- Dépendance intentionnellement nulle : la fonction est pure (aucun I/O, aucun
-- module externe), ce qui facilite les tests unitaires.

--- Renvoie true si `allowed_user` est le wildcard « tout utilisateur ».
is_any_wildcard = (allowed_user) -> tostring(allowed_user) == "_any"

--- Renvoie true si `user` correspond à `allowed_user`
-- (wildcard _any ou correspondance exacte).
matches_user = (allowed_user, user) ->
  is_any_wildcard(allowed_user) or tostring(allowed_user) == tostring(user)

--- Vérifie si un utilisateur qualifie pour une règle donnée.
-- La règle doit avoir `conditions.from_users` (ou `from_userlists`) pour que
-- cette fonction soit pertinente ; en l'absence de ces conditions, tout
-- utilisateur qualifie (retour true).
--
-- @tparam string user            Identifiant de l'utilisateur connecté
-- @tparam table  rule            Entrée de règle avec `.conditions`
-- @tparam table  userlists_cfg   Table `filter.userlists` (peut être {})
-- @treturn boolean
user_qualifies_for_rule = (user, rule, userlists_cfg = {}) ->
  return false unless rule and rule.conditions
  conditions = rule.conditions
  is_array_format = type(conditions[1]) == "table"

  if is_array_format
    for _, cond in ipairs conditions
      continue unless type(cond) == "table"
      for k, v in pairs cond
        if k == "from_users"
          users_list = if type(v) == "table" then v else {v}
          for _, allowed_user in ipairs users_list
            return true if matches_user allowed_user, user
          return false
        if k == "from_userlists"
          list_names = if type(v) == "table" then v else {v}
          for _, list_name in ipairs list_names
            list_users = userlists_cfg[list_name] or {}
            for _, allowed_user in ipairs list_users
              return true if matches_user allowed_user, user
          return false
  else
    for k, v in pairs conditions
      if k == "from_users"
        users_list = if type(v) == "table" then v else {v}
        for _, allowed_user in ipairs users_list
          return true if matches_user allowed_user, user
        return false
      if k == "from_userlists"
        list_names = if type(v) == "table" then v else {v}
        for _, list_name in ipairs list_names
          list_users = userlists_cfg[list_name] or {}
          for _, allowed_user in ipairs list_users
            return true if matches_user allowed_user, user
          return false
  true

{ :user_qualifies_for_rule, :matches_user }
