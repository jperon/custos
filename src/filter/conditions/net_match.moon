-- src/filter/conditions/net_match.moon
-- Bloc commun des conditions CIDR « worker + nft » (from_net, from_subnet,
-- to_net) : conversion Net, eval et compile_nft ne sont écrits qu'ici.

{ :Net } = require "filter.lib.ipcalc"

--- Construit une condition d'appartenance à un CIDR.
-- @tparam table opts {
--   prop:     propriété de `req` à tester ("src_ip" ou "dst_ip"),
--   nft_dir:  direction nft ("saddr" ou "daddr"),
--   net_cidr: CIDR normalisé,
--   subject:  préfixe du message de match (ex. "subnet ", défaut "")
-- }
-- @treturn table Condition enrichie (worker + nft), ou objet « CIDR invalide »
build_cidr_condition = (opts) ->
  { :prop, :nft_dir, :net_cidr } = opts
  subject = opts.subject or ""

  _net = Net net_cidr
  unless _net
    return {
      capabilities: { worker: true, nft: false, nft_dynamic: false }
      net_cidr: net_cidr
      eval: (req) -> false, "Invalid CIDR: #{net_cidr}"
    }

  {
    capabilities: { worker: true, nft: true, nft_dynamic: false }
    net_cidr: net_cidr
    _net: _net
    eval: (req) ->
      ip = req[prop]
      return false, "Missing #{prop}" unless ip
      if _net\contains ip
        true, "#{ip} in #{subject}#{net_cidr}"
      else
        false, "#{ip} not in #{subject}#{net_cidr}"
    compile_nft: (family) ->
      if net_cidr\find ":"
        if family == "inet6" or family == "ip6"
          return "ip6 #{nft_dir} #{net_cidr}", nil
        return nil, "IPv6 CIDR in IPv4 family"
      else
        if family == "inet" or family == "ip"
          return "ip #{nft_dir} #{net_cidr}", nil
        return nil, "IPv4 CIDR in IPv6 family"
  }

{ :build_cidr_condition }
