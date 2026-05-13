-- src/filter/conditions/from_subnet.moon
-- Condition: source IP matches an inline CIDR subnet.
-- API enrichie : support worker + nft.
-- Syntax: { from_subnet: { net: "10.0.0.0/8", family: "inet" } }
-- Also supports simplified syntax: { from_subnet: "10.0.0.0/8" }

(cfg) ->
  (subnet_spec) ->
    unless subnet_spec
      return {
        capabilities: { worker: true, nft_static: false, nft_dynamic: false }
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
        capabilities: { worker: true, nft_static: false, nft_dynamic: false }
        eval: (req) -> false, "Invalid subnet specification"
      }

    { :Net } = require "filter.lib.ipcalc"
    _net = Net net_cidr

    unless _net
      return {
        capabilities: { worker: true, nft_static: false, nft_dynamic: false }
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
          true, "#{ip} in subnet #{net_cidr}"
        else
          false, "#{ip} not in subnet #{net_cidr}"
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
