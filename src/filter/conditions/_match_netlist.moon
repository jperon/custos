-- src/filter/conditions/_match_netlist.moon
-- Condition abstraite : vérifie si une IP appartient à l'un des CIDR
-- d'une liste nommée (nets[name]).
-- Port de shelterfilter conditions/_match_netlist.moon.

--- @tparam string prop Nom de la propriété IP dans req (ex. "src_ip")
-- @treturn function factory (cfg) → (name) → (req) → bool, reason
(prop) ->
  (cfg) -> (name) ->
    _match_net = require("filter.conditions._match_net")(prop)(cfg)
    nets = cfg.nets or {}

    --- @tparam table req {src_ip: string, ...}
    -- @treturn boolean, string
    (req) ->
      netlist = nets[name]
      return false, "Net list '#{name}' not defined" unless netlist
      for cidr in *netlist
        ok = _match_net(cidr)(req)
        return true, "#{req[prop]} in netlist '#{name}'" if ok
      false, "Not in netlist '#{name}'"
