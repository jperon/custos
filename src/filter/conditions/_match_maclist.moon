-- src/filter/conditions/_match_maclist.moon
-- Condition abstraite : vérifie si l'adresse MAC source appartient à un
-- groupe nommé défini dans cfg.macs[name].
-- Analogue de _match_netlist.moon pour les adresses MAC.

--- @tparam string prop Nom de la propriété MAC dans req (ex. "mac")
-- @treturn function factory (cfg) → (name) → (req) → bool, reason
(prop) ->
  (cfg) -> (name) ->
    _match_mac = require("filter.conditions._match_mac")(prop)(cfg)
    macs = cfg.macs or {}

    --- @tparam table req {mac: string, ...}
    -- @treturn boolean, string
    (req) ->
      maclist = macs[name]
      return false, "MAC list '#{name}' not defined" unless maclist
      for mac in *maclist
        ok = _match_mac(mac)(req)
        return true, "#{req[prop]} in maclist '#{name}'" if ok
      false, "Not in maclist '#{name}'"
