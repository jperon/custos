-- src/filter/actions/cname.moon
-- Action : réécrit la réponse DNS en un CNAME synthétique vers la cible
-- configurée (`rule.cname`). Générique — utilisée notamment par les règles
-- SafeSearch (google → forcesafesearch.google.com, etc.).
--
-- La requête est autorisée (eval → allow) afin que la réponse upstream emprunte
-- le pipeline on_response (worker_responses ET doh/query). Le callback remplace
-- alors la réponse par un CNAME : le client re-résout la cible (autorisée par
-- ailleurs). Couvre UDP, TCP et DoH sans forge ni IPC (la réinjection via
-- replace_dns_payload gère déjà les deux transports).

{ :build_cname_response } = require "dns_ede"
dns_mod = require "ipparse.l7.dns"
{ :encode_dns_name } = require "lib.dns_name"
bit = require "bit"

QTYPE_A = dns_mod.types.A
QTYPE_AAAA = dns_mod.types.AAAA
NOERROR = dns_mod.rcodes.NOERROR

_clients = {}
_rr_cache = {}
-- Cache négatif : résolveur upstream injoignable → expires_at. Évite de bloquer
-- le hot-path (worker responses) jusqu'au timeout upstream à CHAQUE paquet vers
-- un résolveur mort (cf. tempête ENOBUFS). Re-sondé après expiration.
_dead_resolvers = {}
DEAD_RESOLVER_TTL = 30   -- secondes (surchargé par cfg.doh.upstream_dead_ttl_s)

pick_resolver_ip = (cfg, ctx) ->
  return ctx.resolver_ip if ctx and ctx.resolver_ip and ctx.resolver_ip != ""
  doh = cfg and cfg.doh or {}
  if doh.prefer_ipv6 and doh.upstream_ipv6 and doh.upstream_ipv6 != ""
    return doh.upstream_ipv6
  doh.upstream_ipv4 or doh.upstream_ipv6

get_upstream_client = (cfg, resolver_ip) ->
  return nil unless resolver_ip and resolver_ip != ""
  cached = _clients[resolver_ip]
  return cached if cached

  ok, upstream_mod = pcall require, "doh.upstream"
  return nil unless ok and upstream_mod

  doh = cfg and cfg.doh or {}
  port = doh.upstream_port or 53
  timeout_ms = doh.upstream_timeout_ms or 2000
  client, _ = upstream_mod.new_client resolver_ip, port, timeout_ms
  _clients[resolver_ip] = client
  client

build_query = (name, qtype, txid) ->
  q = dns_mod.new {
    header: dns_mod.new_header id: txid, rd: true
    questions: {{ qname: encode_dns_name(name), qtype: qtype, qclass: 1 }}
  }
  tostring q

dedupe_raw = (list) ->
  set = {}
  out = {}
  for raw in *list
    unless set[raw]
      set[raw] = true
      out[#out + 1] = raw
  out

resolve_target_rrs = (cfg, target, resolver_ip) ->
  return nil unless target and target != ""
  return nil unless resolver_ip and resolver_ip != ""

  cache_key = "#{resolver_ip}|#{target}"
  now = os.time!
  cached = _rr_cache[cache_key]
  if cached and cached.expires_at > now
    return { a: cached.a, aaaa: cached.aaaa, ttl: cached.ttl }

  -- Cache négatif : si ce résolveur a récemment timeout, on n'essaie pas (sinon
  -- on bloque le worker jusqu'au timeout upstream à chaque paquet).
  dead_until = _dead_resolvers[resolver_ip]
  return nil if dead_until and dead_until > now

  client = get_upstream_client cfg, resolver_ip
  return nil unless client

  records = { a: {}, aaaa: {} }
  ttl = 300
  any_response = false

  for qtype, key in pairs { [QTYPE_A]: "a", [QTYPE_AAAA]: "aaaa" }
    txid = math.random 0, 0xFFFF
    query = build_query target, qtype, txid
    ok, resp_raw = pcall (-> (require "doh.upstream").query client, query)
    if ok and resp_raw
      any_response = true
      resp = dns_mod.parse resp_raw, 1, false
      rcode = resp and resp.header and bit.band(resp.header.ra_z_rcode or 0, 0x0f)
      if resp and resp.header and rcode == NOERROR
        for rr in *(resp.answers or {})
          if rr.rtype == qtype
            if (qtype == QTYPE_A and #rr.rdata == 4) or (qtype == QTYPE_AAAA and #rr.rdata == 16)
              records[key][#records[key] + 1] = rr.rdata
              rr_ttl = tonumber(rr.ttl) or 300
              ttl = rr_ttl if rr_ttl > 0 and rr_ttl < ttl

  -- Aucune réponse des deux requêtes → résolveur injoignable : on le marque mort
  -- pour ne pas re-bloquer le hot-path. Une réponse (même sans A/AAAA) = vivant.
  unless any_response
    dead_ttl = (cfg and cfg.doh and cfg.doh.upstream_dead_ttl_s) or DEAD_RESOLVER_TTL
    _dead_resolvers[resolver_ip] = now + dead_ttl
    return nil
  _dead_resolvers[resolver_ip] = nil

  records.a = dedupe_raw records.a
  records.aaaa = dedupe_raw records.aaaa
  return nil if #records.a == 0 and #records.aaaa == 0

  ttl = 300 if ttl <= 0
  ttl = 30 if ttl < 30
  ttl = 300 if ttl > 300
  records.ttl = ttl

  _rr_cache[cache_key] = {
    a: records.a
    aaaa: records.aaaa
    ttl: records.ttl
    expires_at: now + ttl
  }

  records

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (rule) → enriched_action
_schema = {
  label:       "Réécriture CNAME"
  description: "Réécrit la réponse en un CNAME vers la cible configurée"
  arg_type:    "string"
  arg_hint:    "ex: forcesafesearch.google.com"
}

-- Extrait le nom de la question (FQDN minuscule, sans point final) d'un payload
-- DNS brut. Retourne nil si le paquet n'est pas parsable / sans question.
qname_of = (dns_raw) ->
  return nil unless dns_raw
  ok, dns = pcall (-> dns_mod.parse dns_raw, 1, false)
  return nil unless ok and dns and dns.question and dns.question.name
  name = dns.question.name\lower!
  name\gsub "%.+$", ""

-- Extrait du payload upstream les A/AAAA déjà résolus pour la cible CNAME.
-- L'upstream (notamment un résolveur DoH qui applique lui-même SafeSearch) a
-- souvent déjà renvoyé `target A/AAAA …` : inutile de re-résoudre en UDP/53
-- (coûteux, et impossible si l'upstream est DoH-only ou l'IPv6 injoignable).
-- Retourne { a, aaaa, ttl } ou nil si aucun enregistrement pour la cible.
rrs_from_response = (dns_raw, target) ->
  return nil unless dns_raw and target and target != ""
  ok, dns = pcall (-> dns_mod.parse dns_raw, 1, false)
  return nil unless ok and dns and dns.answers
  want = target\lower!\gsub "%.+$", ""
  a, aaaa = {}, {}
  ttl = 300
  for rr in *dns.answers
    name = rr.name and rr.name\lower!\gsub("%.+$", "")
    continue unless name == want
    if rr.rtype == QTYPE_A and rr.rdata and #rr.rdata == 4
      a[#a + 1] = rr.rdata
    elseif rr.rtype == QTYPE_AAAA and rr.rdata and #rr.rdata == 16
      aaaa[#aaaa + 1] = rr.rdata
    else
      continue
    rr_ttl = tonumber(rr.ttl) or 300
    ttl = rr_ttl if rr_ttl > 0 and rr_ttl < ttl
  return nil if #a == 0 and #aaaa == 0
  { :a, :aaaa, :ttl }

_factory = (cfg) ->
  (rule) ->
    target = rule.cname
    -- Ensemble (optionnel) d'hôtes éligibles à la réécriture. Quand il est défini
    -- (cf. config.build_safesearch_rules), seuls ces noms exacts sont réécrits :
    -- les sous-domaines étrangers (mail.google.com…) qui matchent la condition
    -- `to_domains` par suffixe sont laissés intacts. Absent → comportement
    -- générique historique (réécriture de tout nom matché).
    names = rule.cname_names
    {
      capabilities: { worker: true, nft: false }
      -- Cette action réécrit la destination de la réponse DNS (redirection vers
      -- la cible CNAME). worker_tls s'en sert pour appliquer la même protection
      -- au niveau SNI (bloquer si l'IP de destination n'est pas déjà la cible).
      redirects_destination: true
      cname_target: target
      eval: (req) ->
        nil, "CNAME → #{target} by rule: #{rule.description or '?'}"
      on_response: (ctx) ->
        if names
          qname = qname_of ctx.dns_raw
          return unless qname and names[qname]
        -- Priorité aux A/AAAA déjà fournis par l'upstream pour la cible : évite
        -- une re-résolution UDP/53 redondante (et impossible en upstream DoH /
        -- IPv6 cassé). Sinon, repli sur la résolution directe.
        target_rrs = rrs_from_response ctx.dns_raw, target
        unless target_rrs
          resolver_ip = pick_resolver_ip cfg, ctx
          target_rrs = resolve_target_rrs cfg, target, resolver_ip
        rewritten = build_cname_response nil, ctx.dns_raw, target, ctx.reason, target_rrs
        if rewritten
          ctx.dns_raw  = rewritten
          ctx.modified = true
        has_target_ips = target_rrs and ((#target_rrs.a > 0) or (#target_rrs.aaaa > 0))
        -- Avec A/AAAA résolus, on laisse l'injection nft ajouter les destinations.
        ctx.skip_nft     = not has_target_ips
        ctx.action_label = has_target_ips and "response_cname_resolved" or "response_cname"
      compile_nft: ->
      verdict: ->
        "accept"
    }

{ schema: _schema, factory: _factory, :resolve_target_rrs, :pick_resolver_ip }
