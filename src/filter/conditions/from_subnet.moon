-- src/filter/conditions/from_subnet.moon
-- Condition: source IP matches an inline CIDR subnet.
-- API enrichie : support worker + nft.
-- Syntax: { from_subnet: { net: "10.0.0.0/8", family: "inet" } }
-- Also supports simplified syntax: { from_subnet: "10.0.0.0/8" }

net_match = require "filter.conditions.net_match"

_schema = {
  label:       "Sous-réseau source"
  description: "CIDR IPv4/IPv6 source avec syntaxe inline ou {net,family}"
  category:    "source"
  arg_type:    "string_or_table"
  arg_hint:    "ex: 10.0.0.0/8 ou {net:'10.0.0.0/8'}"
}

_factory = (cfg) ->
  (subnet_spec) ->
    unless subnet_spec
      return {
        capabilities: { worker: true, nft: false, nft_dynamic: false }
        eval: (req) -> false, "from_subnet requires a subnet specification"
      }

    -- Handle both formats
    net_cidr = nil
    if type(subnet_spec) == "string"
      net_cidr = subnet_spec
    elseif type(subnet_spec) == "table" and subnet_spec.net
      net_cidr = subnet_spec.net

    unless net_cidr
      return {
        capabilities: { worker: true, nft: false, nft_dynamic: false }
        eval: (req) -> false, "Invalid subnet specification"
      }

    net_match.build_cidr_condition {
      prop: "src_ip"
      nft_dir: "saddr"
      subject: "subnet "
      :net_cidr
    }

{ schema: _schema, factory: _factory }
