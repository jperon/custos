-- src/filter/conditions/from_net.moon
-- Condition : l'adresse IP source appartient au réseau CIDR configuré.
-- API enrichie : support worker + nft.

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (net_cidr) → enriched_condition
(cfg) ->
  (net_cidr) ->
    -- Gérer les cas spéciaux _any et _none
    if net_cidr == "_any"
      return {
        capabilities: { worker: true, nft_static: false, nft_dynamic: false }
        net_cidr: net_cidr
        eval: (req) ->
          ip = req.src_ip
          ip ~= nil, "src_ip present"
      }
    if net_cidr == "_none"
      return {
        capabilities: { worker: true, nft_static: false, nft_dynamic: false }
        net_cidr: net_cidr
        eval: (req) ->
          ip = req.src_ip
          ip == nil, "src_ip absent"
      }

    -- Cas normal : CIDR valide
    { :Net } = require "filter.lib.ipcalc"
    _net = Net net_cidr
    unless _net
      return {
        capabilities: { worker: true, nft_static: false, nft_dynamic: false }
        net_cidr: net_cidr
        eval: (req) -> false, "Invalid CIDR: #{net_cidr}"
      }

    {
      capabilities: { worker: true, nft_static: true, nft_dynamic: false }
      net_cidr: net_cidr
      _net: _net
      eval: (req) ->
        ip = req.src_ip
        return false, "Missing src_ip" unless ip
        if _net\contains ip
          true, "#{ip} in #{net_cidr}"
        else
          false, "#{ip} not in #{net_cidr}"
      compile_nft: (family) ->
        if net_cidr\find(":")
          if family == "inet6" or family == "ip6"
            return "ip6 saddr #{net_cidr}", nil
          return nil, "IPv6 CIDR in IPv4 family"
        else
          if family == "inet" or family == "ip"
            return "ip saddr #{net_cidr}", nil
          return nil, "IPv4 CIDR in IPv6 family"
    }
