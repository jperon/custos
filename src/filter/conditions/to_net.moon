-- src/filter/conditions/to_net.moon
-- Condition : l'adresse IP destination appartient au réseau CIDR configuré.
-- API enrichie : support worker + nft.

net_match = require "filter.conditions.net_match"

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (net_cidr) → enriched_condition
_schema = {
  label:       "Réseau destination"
  description: "Requête vers un CIDR IPv4/IPv6 de destination (support nft natif)"
  category:    "destination"
  arg_type:    "string"
  arg_hint:    "ex: 10.0.0.0/8"
}

_factory = (cfg) ->
  (net_cidr) ->
    -- Gérer les cas spéciaux _any et _none
    if net_cidr == "_any"
      return {
        capabilities: { worker: true, nft: false, nft_dynamic: false }
        net_cidr: net_cidr
        eval: (req) ->
          ip = req.dst_ip
          ip ~= nil, "dst_ip present"
      }
    if net_cidr == "_none"
      return {
        capabilities: { worker: true, nft: false, nft_dynamic: false }
        net_cidr: net_cidr
        eval: (req) ->
          ip = req.dst_ip
          ip == nil, "dst_ip absent"
      }

    net_match.build_cidr_condition {
      prop: "dst_ip"
      nft_dir: "daddr"
      :net_cidr
    }

{ schema: _schema, factory: _factory }
