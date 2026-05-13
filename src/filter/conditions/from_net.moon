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
        worker_only: true
        net_cidr: net_cidr
        eval: (req) ->
          ip = req.src_ip
          ip ~= nil, "src_ip present"
        compile_nft: -> nil, "_any not supported in nft"
        creates_dynamic_scope: false
      }
    if net_cidr == "_none"
      return {
        capabilities: { worker: true, nft_static: false, nft_dynamic: false }
        worker_only: true
        net_cidr: net_cidr
        eval: (req) ->
          ip = req.src_ip
          ip == nil, "src_ip absent"
        compile_nft: -> nil, "_none not supported in nft"
        creates_dynamic_scope: false
      }

    -- Cas normal : CIDR valide
    { :Net } = require "filter.lib.ipcalc"
    _net = Net net_cidr
    unless _net
      return {
        capabilities: { worker: true, nft_static: false, nft_dynamic: false }
        worker_only: true
        net_cidr: net_cidr
        eval: (req) -> false, "Invalid CIDR: #{net_cidr}"
        compile_nft: -> nil, "invalid CIDR"
        creates_dynamic_scope: false
      }

    {
      capabilities: { worker: true, nft_static: true, nft_dynamic: false }
      worker_only: false
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
        -- Détecter si c'est IPv4 ou IPv6 selon le CIDR
        if net_cidr\find(":")
          -- IPv6
          if family == "inet6" or family == "ip6"
            return "ip6 saddr #{net_cidr}", nil
          return nil, "IPv6 CIDR in IPv4 family"
        else
          -- IPv4
          if family == "inet" or family == "ip"
            return "ip saddr #{net_cidr}", nil
          return nil, "IPv4 CIDR in IPv6 family"
      creates_dynamic_scope: false
    }
