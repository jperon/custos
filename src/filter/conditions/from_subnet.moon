-- src/filter/conditions/from_subnet.moon
-- Condition: source IP matches an inline CIDR subnet.
-- Syntax: { from_subnet: { net: "10.0.0.0/8", family: "inet" } }
-- Also supports simplified syntax: { from_subnet: "10.0.0.0/8" }

(cfg) -> (subnet_spec) ->
  unless subnet_spec
    return (req) ->
      false, "from_subnet requires a subnet specification"

  -- Handle both formats:
  -- 1. { net: "10.0.0.0/8", family: "inet" }
  -- 2. "10.0.0.0/8"
  net_cidr = nil
  if type(subnet_spec) == "string"
    net_cidr = subnet_spec
  elseif type(subnet_spec) == "table" and subnet_spec.net
    net_cidr = subnet_spec.net
  
  unless net_cidr
    return (req) ->
      false, "Invalid subnet specification"

  { :Net } = require "filter.lib.ipcalc"
  _net = Net net_cidr

  if _net
    (req) ->
      ip = req.src_ip
      unless ip
        return false, "Missing src_ip"
      if _net\contains ip
        true, "#{ip} in subnet #{net_cidr}"
      else
        false, "#{ip} not in subnet #{net_cidr}"
  else
    (req) -> false, "Invalid CIDR: #{net_cidr}"
