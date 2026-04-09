-- src/filter/conditions/stolen_computer.moon
-- Condition : l'équipement source est dans une liste noire de MACs.
-- Dans custos, la liste est une table directe de chaînes MAC
-- (pas de lookup via cfg.computers comme dans shelterfilter).

--- @tparam table cfg Configuration du filtre (non utilisée ici)
-- @treturn function factory (macs: table) → (req) → bool, reason
(cfg) -> (macs) ->
  blacklist = {}
  for _, mac in ipairs macs
    blacklist[mac\lower!] = true

  --- @tparam table req {mac: string, ...}
  -- @treturn boolean, string
  (req) ->
    _mac = req.mac
    return false, "MAC not available" unless _mac
    if blacklist[_mac\lower!]
      true, "Stolen computer: #{_mac}"
    else
      false, "MAC #{_mac} not in blacklist"
