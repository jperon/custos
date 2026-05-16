-- src/filter/conditions/to_nets.moon
-- Condition : l'IP destination appartient à l'un des CIDRs listés inline.
-- API enrichie : support nft avec set inline ou multiple expressions.

--- @tparam table cfg Configuration
-- @treturn function factory (cidrs) → enriched_condition
(cfg) ->
  (cidrs) ->
    unless type(cidrs) == "table"
      return {
        capabilities: { worker: true, nft: false, nft_dynamic: false }
        eval: (req) -> false, "to_nets requires a table of CIDRs"
      }

    -- Pre-compile nets
    { :Net } = require "filter.lib.ipcalc"
    nets = {}
    for _, cidr in ipairs cidrs
      net = Net cidr
      if net
        nets[#nets + 1] = { :net, :cidr }

    {
      capabilities: { worker: true, nft: true, nft_dynamic: false }
      cidrs: cidrs
      eval: (req) ->
        ip = req.dst_ip
        return false, "dst_ip not available" unless ip
        for _, entry in ipairs nets
          if entry.net\contains ip
            return true, "#{ip} in #{entry.cidr}"
        false, "#{ip} not in any CIDR"
      compile_nft: (family) ->
        -- Inline CIDR list: { 192.168.1.0/24, 10.0.0.0/8 }
        cidr_str = table.concat(cidrs, ", ")
        is_ipv6 = cidrs[1] and cidrs[1]\find(":")
        if is_ipv6
          return "ip6 daddr { #{cidr_str} }", nil
        else
          return "ip daddr { #{cidr_str} }", nil
    }
