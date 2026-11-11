local net_match = require("filter.conditions.net_match")
local _schema = {
  label = "Réseau destination",
  description = "Requête vers un CIDR IPv4/IPv6 de destination (support nft natif)",
  category = "destination",
  arg_type = "string",
  arg_hint = "ex: 10.0.0.0/8 ou alias de filter.nets"
}
local _factory
_factory = function(cfg)
  return function(net_cidr)
    if net_cidr == "_any" then
      return {
        capabilities = {
          worker = true,
          nft = false,
          nft_dynamic = false
        },
        net_cidr = net_cidr,
        eval = function(req)
          local ip = req.dst_ip
          return ip ~= nil, "dst_ip present"
        end
      }
    end
    if net_cidr == "_none" then
      return {
        capabilities = {
          worker = true,
          nft = false,
          nft_dynamic = false
        },
        net_cidr = net_cidr,
        eval = function(req)
          local ip = req.dst_ip
          return ip == nil, "dst_ip absent"
        end
      }
    end
    return net_match.build_net_arg_condition(cfg, {
      prop = "dst_ip",
      nft_dir = "daddr",
      cond_name = "to_net",
      net_cidr = net_cidr
    })
  end
end
return {
  schema = _schema,
  factory = _factory
}
