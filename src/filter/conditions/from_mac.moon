-- src/filter/conditions/from_mac.moon
-- Condition : l'équipement source a l'adresse MAC configurée.
-- API enrichie : support worker + nft.

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (mac_or_alias) → enriched_condition
_schema = {
  label:       "Adresse MAC source"
  description: "Requête depuis une adresse MAC spécifique (support nft natif)"
  category:    "source"
  arg_type:    "string"
  arg_hint:    "ex: aa:bb:cc:dd:ee:ff"
}

_factory = (cfg) ->
  (mac_or_alias) ->
    mac_map = cfg.macs or {}

    -- Résolution de l'alias vers la MAC réelle
    target_mac = nil
    if mac_or_alias and mac_or_alias ~= "_any" and mac_or_alias ~= "_none"
      target_mac = (mac_map[mac_or_alias] or mac_or_alias)\lower!

    -- Cas spéciaux _any et _none
    if mac_or_alias == "_any"
      return {
        capabilities: { worker: true, nft: false, nft_dynamic: false }
        mac_or_alias: mac_or_alias
        eval: (req) ->
          _mac = req.mac
          _mac ~= nil, "MAC available"
      }
    if mac_or_alias == "_none"
      return {
        capabilities: { worker: true, nft: false, nft_dynamic: false }
        mac_or_alias: mac_or_alias
        eval: (req) ->
          _mac = req.mac
          _mac == nil, "MAC not available"
      }

    -- Cas normal : MAC spécifique
    {
      capabilities: { worker: true, nft: true, nft_dynamic: false }
      mac_or_alias: mac_or_alias
      target_mac: target_mac
      eval: (req) ->
        _mac = req.mac
        return false, "MAC not available" unless _mac
        _mac\lower! == target_mac, "MAC #{_mac} vs #{target_mac}"
      compile_nft: (family) ->
        return "ether saddr #{target_mac}", nil
    }

{ schema: _schema, factory: _factory }
