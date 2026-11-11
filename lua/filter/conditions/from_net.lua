local net_match = require("filter.conditions.net_match")
local _schema = {
  label = "Réseau source",
  description = "Requête provenant d'un CIDR IPv4 ou IPv6 (support nft natif)",
  category = "source",
  arg_type = "string",
  arg_hint = "ex: 192.168.0.0/24"
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
          local ip = req.src_ip
          return ip ~= nil, "src_ip present"
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
          local ip = req.src_ip
          return ip == nil, "src_ip absent"
        end
      }
    end
    return net_match.build_cidr_condition({
      prop = "src_ip",
      nft_dir = "saddr",
      net_cidr = net_cidr
    })
  end
end
return {
  schema = _schema,
  factory = _factory
}
