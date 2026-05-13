-- src/filter/conditions/from_maclists.moon
-- Condition : l'adresse MAC source appartient à l'une des listes nommées (cfg.macs).
-- API enrichie : worker-only (multiple lists complex in nft).

--- @tparam table cfg Configuration
-- @treturn function factory (list_names) → enriched_condition
(cfg) ->
  (list_names) ->
    lists = list_names
    unless type(list_names) == "table"
      lists = { list_names }
    
    {
      capabilities: { worker: true, nft_static: false, nft_dynamic: false }
      lists: lists
      eval: (req) ->
        _mac = req.mac
        return false, "mac not available" unless _mac
        _mac_lower = _mac\lower!
        for _, list_name in ipairs lists
          macs = cfg.macs and cfg.macs[list_name] or {}
          for _, mac in ipairs macs
            return true, "mac #{_mac} in #{list_name}" if _mac_lower == mac\lower!
        false, "mac #{_mac} not in any list"
    }
