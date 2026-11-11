local net_match = require("filter.conditions.net_match")
local _schema = {
  label = "Sous-réseau source",
  description = "CIDR IPv4/IPv6 source avec syntaxe inline ou {net,family}",
  category = "source",
  arg_type = "string_or_table",
  arg_hint = "ex: 10.0.0.0/8 ou {net:'10.0.0.0/8'}"
}
local _factory
_factory = function(cfg)
  return function(subnet_spec)
    if not (subnet_spec) then
      return {
        capabilities = {
          worker = true,
          nft = false,
          nft_dynamic = false
        },
        eval = function(req)
          return false, "from_subnet requires a subnet specification"
        end
      }
    end
    local net_cidr = nil
    if type(subnet_spec) == "string" then
      net_cidr = subnet_spec
    elseif type(subnet_spec) == "table" and subnet_spec.net then
      net_cidr = subnet_spec.net
    end
    if not (net_cidr) then
      return {
        capabilities = {
          worker = true,
          nft = false,
          nft_dynamic = false
        },
        eval = function(req)
          return false, "Invalid subnet specification"
        end
      }
    end
    return net_match.build_cidr_condition({
      prop = "src_ip",
      nft_dir = "saddr",
      subject = "subnet ",
      net_cidr = net_cidr
    })
  end
end
return {
  schema = _schema,
  factory = _factory
}
