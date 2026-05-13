-- src/filter/conditions/from_netlists.moon
-- Condition : l'adresse IP source appartient à au moins une des netlists.
-- API enrichie : worker-only (multiple netlists complex in nft).

--- @tparam table cfg Configuration
-- @treturn function factory (list_names) → enriched_condition
(cfg) ->
  (list_names) ->
    lists = list_names
    unless type(list_names) == "table"
      lists = { list_names }
    
    {
      capabilities: { worker: true, nft_static: false, nft_dynamic: false }
      lists: lists
      eval: (req) ->
        ip = req.src_ip
        return false, "src_ip not available" unless ip
        { :Net } = require "filter.lib.ipcalc"
        for _, list_name in ipairs lists
          nets = cfg.nets and cfg.nets[list_name] or {}
          for _, cidr in ipairs nets
            net = Net cidr
            if net and net\contains ip
              return true, "#{ip} in #{cidr} (#{list_name})"
        false, "#{ip} not in any netlist"
    }
