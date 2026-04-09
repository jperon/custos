-- src/filter/conditions/_match_netlists.moon
-- Condition abstraite : vérifie si une IP appartient à au moins une
-- des netlists nommées.
-- Port de shelterfilter conditions/_match_netlists.moon.

--- @tparam string prop Nom de la propriété IP dans req (ex. "src_ip")
-- @treturn function factory (cfg) → (names: table) → (req) → bool, reason
(prop) ->
  (cfg) -> (names) ->
    _match_netlist = require("filter.conditions._match_netlist")(prop)(cfg)

    --- @tparam table req {src_ip: string, ...}
    -- @treturn boolean, string
    (req) ->
      for _, name in ipairs names
        ok = _match_netlist(name)(req)
        return true, "In one of: #{table.concat names, ', '}" if ok
      false, "Not in any of: #{table.concat names, ', '}"
