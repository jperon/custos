-- src/filter/conditions/_match_mac.moon
-- Condition abstraite : vérifie si l'adresse MAC source correspond.
-- Supporte les adresses MAC brutes ou les alias définis dans cfg.macs.
--
-- Paramètres spéciaux :
-- - _any : match si la MAC est présente dans la requête.
-- - _none : match si la MAC est absente de la requête.
--- @tparam string prop Nom de la propriété MAC dans req (ex. "mac")
-- @treturn function factory (cfg) → (mac_or_alias) → (req) → bool
(prop) ->
  (cfg) -> (mac_or_alias) ->
    mac_map = cfg.macs or {}

    -- Résolution de l'alias vers la MAC réelle (si ce n'est pas un mot-clé)
    target_mac = nil
    if mac_or_alias and mac_or_alias ~= "_any" and mac_or_alias ~= "_none"
      target_mac = (mac_map[mac_or_alias] or mac_or_alias)\lower!

    --- @tparam table req {mac: string, src_ip: string, ...}
    -- @treturn boolean, string
    (req) ->
      _mac = req[prop]

      if mac_or_alias == "_any"
        return _mac ~= nil, "MAC available"
      if mac_or_alias == "_none"
        return _mac == nil, "MAC not available"

      return false, "MAC not available in request" unless _mac
      _mac\lower! == target_mac, "MAC #{_mac} vs #{target_mac} (#{mac_or_alias})"
