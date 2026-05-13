-- src/filter/conditions/stolen_computer.moon
-- Condition : vérifie si l'adresse MAC source est dans une liste noire d'ordinateurs volés.
-- API enrichie: support nft avec set inline.

--- @tparam table cfg Configuration
-- @treturn function factory (macs) → enriched_condition
(cfg) ->
  (macs) ->
    unless type(macs) == "table"
      return {
        capabilities: { worker: true, nft_static: false, nft_dynamic: false }
        worker_only: true
        eval: (req) -> false, "stolen_computer requires a table of MACs"
        compile_nft: -> nil, "invalid macs"
        creates_dynamic_scope: false
      }
    
    blacklist = {}
    macs_lower = {}
    for mac in *macs
      mac_lower = mac\lower!
      blacklist[mac_lower] = true
      macs_lower[#macs_lower + 1] = mac_lower
    
    {
      capabilities: { worker: true, nft_static: true, nft_dynamic: false }
      worker_only: false
      macs: macs
      eval: (req) ->
        _mac = req.mac
        unless _mac
          return false, "MAC not available"
        if blacklist[_mac\lower!]
          return true, "Stolen computer: #{_mac}"
        else
          return false, "MAC #{_mac} not in blacklist"
      compile_nft: (family) ->
        mac_str = table.concat(macs_lower, ", ")
        return "ether saddr { #{mac_str} }", nil
      creates_dynamic_scope: false
    }
