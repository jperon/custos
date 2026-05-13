-- src/filter/conditions/from_netlist.moon
-- Condition : l'adresse IP source appartient à une netlist nommée.
-- API enrichie : support sets nft pour les netlists.

--- @tparam table cfg Configuration
-- @treturn function factory (list_name) → enriched_condition
(cfg) ->
  (list_name) ->
    nets = cfg.nets and cfg.nets[list_name] or {}
    
    {
      capabilities: { worker: true, nft_static: true, nft_dynamic: false }
      worker_only: false
      list_name: list_name
      nets: nets
      eval: (req) ->
        ip = req.src_ip
        return false, "src_ip not available" unless ip
        { :Net } = require "filter.lib.ipcalc"
        for _, cidr in ipairs nets
          net = Net cidr
          if net and net\contains ip
            return true, "#{ip} in #{cidr} (#{list_name})"
        false, "#{ip} not in #{list_name}"
      compile_nft: (family) ->
        -- Determine if IPv4 or IPv6 based on first entry
        set_name = "nets_#{list_name}"
        is_ipv6 = nets[1] and nets[1]\find(":")
        if is_ipv6
          return "ip6 saddr @#{set_name}", nil
        else
          return "ip saddr @#{set_name}", nil
      creates_dynamic_scope: false
    }
