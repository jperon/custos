-- src/filter/conditions/_match_maclists.moon
-- Condition abstraite : vérifie si l'adresse MAC source appartient à au
-- moins un des groupes nommés dans cfg.macs.
-- Analogue de _match_netlists.moon pour les adresses MAC.

--- @tparam string prop Nom de la propriété MAC dans req (ex. "mac")
-- @treturn function factory (cfg) → (names: table) → (req) → bool, reason
(prop) ->
  (cfg) -> (names) ->
    _match_maclist = require("filter.conditions._match_maclist")(prop)(cfg)

    --- @tparam table req {mac: string, ...}
    -- @treturn boolean, string
    (req) ->
      for _, name in ipairs names
        ok = _match_maclist(name)(req)
        return true, "In one of: #{table.concat names, ', '}" if ok
      false, "Not in any of: #{table.concat names, ', '}"
