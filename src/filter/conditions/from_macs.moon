-- src/filter/conditions/from_macs.moon
-- Condition : l'adresse MAC source correspond à l'une des MACs listées inline.
-- API enrichie : support nft avec set inline.

--- @tparam table cfg Configuration
-- @treturn function factory (macs) → enriched_condition
(cfg) ->
  (macs) ->
    unless type(macs) == "table"
      return {
        capabilities: { worker: true, nft: false, nft_dynamic: false }
        eval: (req) -> false, "from_macs requires a table of MACs"
      }
    
    -- Normalize MACs to lowercase
    macs_lower = [mac\lower! for mac in *macs]
    
    {
      capabilities: { worker: true, nft: true, nft_dynamic: false }
      macs: macs
      eval: (req) ->
        _mac = req.mac
        return false, "mac not available" unless _mac
        _mac_lower = _mac\lower!
        for _, mac in ipairs macs_lower
          return true, "mac #{_mac} matched" if _mac_lower == mac
        false, "mac #{_mac} not in list"
      compile_nft: (family) ->
        -- Inline MAC list: ether saddr { aa:bb:cc:dd:ee:ff, 11:22:33:44:55:66 }
        mac_str = table.concat(macs_lower, ", ")
        return "ether saddr { #{mac_str} }", nil
    }
