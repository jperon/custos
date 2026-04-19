-- src/filter/conditions/_match_mac.moon
-- Condition abstraite : vérifie si l'adresse MAC source correspond.
-- Supporte les adresses MAC brutes ou les alias définis dans cfg.macs.
--- @tparam string prop Nom de la propriété MAC dans req (ex. "mac")
-- @treturn function factory (cfg) → (mac_or_alias) → (req) → bool
(prop) ->
  (cfg) -> (mac_or_alias) ->
    mac_map = cfg.macs or {}
    
    -- Résolution de l'alias vers la MAC réelle
    target_mac = mac_map[mac_or_alias] or mac_or_alias
    target_mac = target_mac\lower!

    --- @tparam table req {mac: string, src_ip: string, ...}
    -- @treturn boolean, string
    (req) ->
      _mac = req[prop]
      return false, "MAC not available in request" unless _mac
      _mac\lower! == target_mac, "MAC #{_mac} vs #{target_mac} (#{mac_or_alias})"