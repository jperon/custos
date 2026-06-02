-- src/filter/localnets.moon
-- Détecte les réseaux locaux attachés au bridge pour les ajouter à la whitelist.
{ :log_info, :log_warn } = require "log"
{ :ffi, :libc } = require "ffi_defs"

--- Récupère le nom du bridge
-- @tparam table auth_cfg Configuration auth (bridge_ifname normalement résolu par config)
-- @treturn string Nom de l'interface bridge
get_bridge_ifname = (auth_cfg) ->
  (auth_cfg and auth_cfg.bridge_ifname) or "br0"

--- Extrait les CIDR locaux depuis la table de routage
-- @tparam string ifname Interface à analyser
-- @treturn table {ipv4: {string}, ipv6: {string}}
get_local_cidrs = (ifname) ->
  cidrs = {
    ipv4: {}
    ipv6: {}
  }
  
  -- IPv4 routes
  res4 = io.popen "ip -4 route show dev #{ifname}"
  if res4
    for line in res4\lines!
      -- On cherche les réseaux (ex: 10.35.1.0/24)
      cidr = line\match "([0-9%.]+/[0-9]+)"
      if cidr
        mask = cidr\match "/(%d+)$"
        if mask and tonumber(mask) >= 8
          table.insert cidrs.ipv4, cidr
    res4\close!
  
  -- IPv6 routes
  res6 = io.popen "ip -6 route show dev #{ifname}"
  if res6
    for line in res6\lines!
      cidr = line\match "([%x%a%:]+/[0-9]+)"
      if cidr
        mask = cidr\match "/(%d+)$"
        if mask and tonumber(mask) >= 48
          table.insert cidrs.ipv6, cidr
    res6\close!
    
  cidrs

--- Injecte les réseaux locaux dans la whitelist
-- @tparam table auth_cfg Configuration auth
-- @tparam table whitelist Table des destinations autorisées
-- @treturn nil
inject_localnets = (auth_cfg, whitelist) ->
  unless auth_cfg and auth_cfg.allow_localnets
    return

  ifname = get_bridge_ifname auth_cfg
  cidrs = get_local_cidrs ifname
  
  count = 0
  for _, net in ipairs cidrs.ipv4
    table.insert whitelist, net
    count += 1
  for _, net in ipairs cidrs.ipv6
    table.insert whitelist, net
    count += 1
  
  log_info -> { action: "localnets_injected", bridge: ifname, count: count }

{ :inject_localnets, :get_bridge_ifname }
