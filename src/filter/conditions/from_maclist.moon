-- src/filter/conditions/from_maclist.moon
-- Condition : l'adresse MAC source appartient à une liste nommée (cfg.macs).
-- API enrichie : support sets nft pour les listes MAC.

--- @tparam table cfg Configuration
-- @treturn function factory (list_name) → enriched_condition
(cfg) ->
  (list_name) ->
    macs = cfg.macs and cfg.macs[list_name] or {}
    
    {
      capabilities: { worker: true, nft_static: true, nft_dynamic: false }
      list_name: list_name
      macs: macs
      eval: (req) ->
        _mac = req.mac
        return false, "mac not available" unless _mac
        _mac_lower = _mac\lower!
        for _, mac in ipairs macs
          return true, "mac #{_mac} in #{list_name}" if _mac_lower == mac\lower!
        false, "mac #{_mac} not in #{list_name}"
      compile_nft: (family) ->
        set_name = "macs_#{list_name}"
        return "ether saddr @#{set_name}", nil
    }
