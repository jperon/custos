-- src/filter/conditions/_match_net.moon
-- Condition abstraite : vérifie si une adresse IP appartient à un réseau CIDR.
-- Supporte les valeurs spéciales "_any" (IP présente) et "_none" (IP absente).
-- Port de shelterfilter conditions/_match_net.moon, adapté pour ipcalc FFI.

--- @tparam string prop Nom de la propriété IP dans req (ex. "src_ip")
-- @treturn function factory (cfg) → (net_cidr) → (req) → bool, reason
(prop) ->
  (cfg) -> (net_cidr) ->
    if net_cidr == "_any"
      return (req) ->
        ip = req[prop]
        ip ~= nil, "#{prop} present"
    if net_cidr == "_none"
      return (req) ->
        ip = req[prop]
        ip == nil, "#{prop} absent"

    { :Net } = require "filter.lib.ipcalc"
    _net = Net net_cidr
    if _net
      --- @tparam table req {src_ip: string, ...}
      -- @treturn boolean, string
      (req) ->
        ip = req[prop]
        return false, "Missing #{prop}" unless ip
        if _net\contains ip
          true, "#{ip} in #{net_cidr}"
        else
          false, "#{ip} not in #{net_cidr}"
    else
      (req) -> false, "Invalid CIDR: #{net_cidr}"
