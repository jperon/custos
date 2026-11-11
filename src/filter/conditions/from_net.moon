-- src/filter/conditions/from_net.moon
-- Condition : l'adresse IP source appartient au réseau CIDR configuré.
-- API enrichie : support worker + nft.

net_match = require "filter.conditions.net_match"

_schema = {
  label:       "Réseau source"
  description: "Requête provenant d'un CIDR IPv4 ou IPv6 (support nft natif)"
  category:    "source"
  arg_type:    "string"
  arg_hint:    "ex: 192.168.0.0/24 ou alias de filter.nets"
}

_factory = (cfg) ->
  (net_cidr) ->
    -- Gérer les cas spéciaux _any et _none
    if net_cidr == "_any"
      return {
        capabilities: { worker: true, nft: false, nft_dynamic: false }
        net_cidr: net_cidr
        eval: (req) ->
          ip = req.src_ip
          ip ~= nil, "src_ip present"
      }
    if net_cidr == "_none"
      return {
        capabilities: { worker: true, nft: false, nft_dynamic: false }
        net_cidr: net_cidr
        eval: (req) ->
          ip = req.src_ip
          ip == nil, "src_ip absent"
      }

    net_match.build_net_arg_condition(cfg, {
      prop: "src_ip"
      nft_dir: "saddr"
      cond_name: "from_net"
      :net_cidr
    })

{ schema: _schema, factory: _factory }
