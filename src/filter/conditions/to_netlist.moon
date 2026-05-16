-- src/filter/conditions/to_netlist.moon
-- Condition : l'adresse IP destination appartient à une netlist nommée.
-- API enrichie : support sets nft pour les netlists.

--- @tparam table cfg Configuration
-- @treturn function factory (list_name) → enriched_condition
(cfg) ->
  { :Net } = require "filter.lib.ipcalc"
  (list_name) ->
    raw_nets = cfg.nets and cfg.nets[list_name] or {}

    -- Pré-compiler les CIDRs à l'init
    compiled = {}
    for _, cidr in ipairs raw_nets
      net = Net cidr
      compiled[#compiled + 1] = { :net, :cidr } if net

    {
      capabilities: { worker: true, nft: true, nft_dynamic: false }
      list_name: list_name
      nets: raw_nets
      eval: (req) ->
        ip = req.dst_ip
        return false, "dst_ip not available" unless ip
        for _, entry in ipairs compiled
          if entry.net\contains ip
            return true, "#{ip} in #{entry.cidr} (#{list_name})"
        false, "#{ip} not in #{list_name}"
      compile_nft: (family) ->
        set_name = "nets_#{list_name}"
        is_ipv6 = raw_nets[1] and raw_nets[1]\find(":")
        if is_ipv6
          return "ip6 daddr @#{set_name}", nil
        else
          return "ip daddr @#{set_name}", nil
    }
