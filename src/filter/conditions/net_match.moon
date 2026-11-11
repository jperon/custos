-- src/filter/conditions/net_match.moon
-- Bloc commun des conditions CIDR « worker + nft » (from_net, from_subnet,
-- to_net) : conversion Net, eval et compile_nft ne sont écrits qu'ici.
-- Résout aussi les alias de `filter.nets` pour from_net/to_net.

{ :Net } = require "filter.lib.ipcalc"
compiler_api = require "filter.compiler_api"
log = require "log"

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

-- Normalise la valeur d'un alias `filter.nets` en liste de CIDRs.
net_alias_cidrs = (value) ->
  return {} if value == nil
  return {value} if type(value) == "string"
  return value if type(value) == "table"
  {}

-- Construit une condition OR sur les CIDRs d'un alias `filter.nets`.
-- Un groupe de plusieurs CIDRs est déclaré worker-only : make_plural produit
-- une expression nft déjà groupée (« ip saddr { … } ») que le merge du niveau
-- supérieur (from_nets, from_net_list…) ne sait pas recombiner sans fabriquer
-- une expression invalide. Un alias vers un seul CIDR reste nft-capable.
build_alias_condition = (cfg, opts, group) ->
  cidrs = net_alias_cidrs group
  base_factory = (c) ->
    (item) ->
      build_cidr_condition {
        prop: opts.prop
        nft_dir: opts.nft_dir
        subject: opts.subject
        net_cidr: item
      }
  cond = compiler_api.make_plural(base_factory)(cfg)(cidrs)
  if #cidrs > 1
    cond.capabilities = { worker: true, nft: false, nft_dynamic: false }
    cond.compile_nft = -> nil, "multi-CIDR alias is worker-only"
  cond

--- Construit une condition d'appartenance pour un argument from_net/to_net.
-- Un argument qui n'est ni `_any`/`_none` ni un CIDR/IP littéral mais une clé
-- de `cfg.nets` est résolu vers le ou les CIDRs du groupe (OU logique).
-- @tparam table cfg Configuration du filtre (lit `cfg.nets`)
-- @tparam table opts { prop, nft_dir, net_cidr, subject?, cond_name? }
-- @treturn table Condition enrichie (worker + nft)
build_net_arg_condition = (cfg, opts) ->
  net_cidr = opts.net_cidr
  is_literal = type(net_cidr) == "string" and (Net net_cidr) != nil
  special = net_cidr == "_any" or net_cidr == "_none"
  if type(net_cidr) == "string" and not is_literal and not special
    nets = (cfg and cfg.nets) or {}
    group = nets[net_cidr]
    if group != nil
      cond = build_alias_condition cfg, opts, group
      cond.net_alias = net_cidr
      return cond
    -- Un seul avertissement à la CONSTRUCTION (jamais dans eval, chaud).
    -- Lecture de log_warn au call-site : certains specs remplacent le stub
    -- `log` par une table partielle (sans log_warn).
    warn = log.log_warn
    if warn
      warn -> {
        action: "filter_net_unknown"
        condition: opts.cond_name or "net"
        net: net_cidr
      }
  build_cidr_condition opts

{ :build_cidr_condition, :build_net_arg_condition }
