-- src/filter/conditions/to_netlist.moon
-- Condition : l'adresse IP destination appartient à une netlist nommée.
-- API enrichie : support sets nft pour les netlists.

--- @tparam table cfg Configuration
-- @treturn function factory (list_name) → enriched_condition
(cfg) ->
  { :Net } = require "filter.lib.ipcalc"
  (list_name) ->
    -- Support multiple config structures (merge all locations):
    -- - Full config: cfg.nets or cfg.filter.netlists
    -- - Filter config: cfg.netlists
    -- Check all locations (not short-circuiting with or)
    raw_nets = cfg.nets and cfg.nets[list_name] or
                cfg.netlists and cfg.netlists[list_name] or
                (cfg.filter and cfg.filter.netlists and cfg.filter.netlists[list_name]) or {}
    -- If raw_nets is a string (single CIDR), wrap it in a table
    if type(raw_nets) == "string"
      raw_nets = { raw_nets }

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
        -- Use family-specific set names for nft compilation
        if family == "ip6"
          return "ip6 daddr @#{set_name}6", nil
        else
          return "ip daddr @#{set_name}", nil
    }
