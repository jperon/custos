-- src/response_inject.moon
-- Noyau commun d'injection nft des réponses DNS, partagé par worker_responses
-- (plan de données NFQUEUE) et doh/query (proxy DoH).
--
-- Responsabilités factorisées :
--   - rr_timeout        : TTL du RR → timeout de set nft (borné + grace)
--   - detect_wildcards  : règles wildcard d'auth (from_users sans to_domain*)
--   - inject            : boucle d'injection A/AAAA (per-rule + mac + wildcard),
--                         avec comptage records_to_add/success pour le fail-closed.
--
-- Le module ne tire AUCUNE dépendance nft directe : les fonctions d'ajout
-- (add_ip4_many/6, add_mac4_many/6) sont injectées via `opts`, ce qui le rend
-- testable unitairement sans libnftnl.

config = require "config"

dns_cfg = config.dns or {}
ttl_cfg = dns_cfg.ttl_grace or {}

clamp = (value, min_v, max_v) ->
  return min_v if value < min_v
  return max_v if value > max_v
  value

--- Convertit le TTL d'un RR en timeout de set nft (string + secondes).
-- Applique grace puis borne dans [min, max] (config.dns.ttl_grace).
-- @tparam number|string ttl TTL brut du RR.
-- @treturn string Timeout au format nft (ex. "660s").
-- @treturn number Timeout effectif en secondes.
rr_timeout = (ttl) ->
  grace = math.max 0, math.floor(tonumber(ttl_cfg.grace) or 600)
  min_t = math.max 1, math.floor(tonumber(ttl_cfg.min) or 60)
  max_t = math.max min_t, math.floor(tonumber(ttl_cfg.max) or 2592000)

  rr_ttl = tonumber(ttl) or 0
  rr_ttl = math.floor rr_ttl
  rr_ttl = 0 if rr_ttl < 0
  effective = clamp rr_ttl + grace, min_t, max_t
  tostring(effective) .. "s", effective

--- Détecte les rule_id des règles wildcard d'auth.
-- Une règle wildcard d'auth exige une authentification (from_users /
-- from_userlists) SANS restreindre de domaine (aucune to_domains /
-- to_domainlist) : elle autorise un utilisateur authentifié vers n'importe
-- quelle destination. Les IPs résolues doivent être recopiées dans ses sets.
-- @tparam table rules_metadata Métadonnées de règles compilées.
-- @treturn table Liste de rule_id (possiblement vide).
detect_wildcards = (rules_metadata) ->
  out = {}
  for idx, meta in ipairs rules_metadata or {}
    requires_auth = false
    dns_refs = 0
    if meta.conditions
      for _, cond in ipairs meta.conditions
        if cond.name == "from_users" or cond.name == "from_userlists"
          requires_auth = true
        if cond.name == "to_domains" or cond.name == "to_domainlist"
          dns_refs += 1
    if requires_auth and dns_refs == 0
      out[#out + 1] = meta.rule_id or "unknown_#{idx}"
  out

--- Boucle d'injection nft des réponses A/AAAA (noyau commun).
-- Les insertions sont regroupées par set et par timeout : une réponse de N RR
-- ne coûte plus 2N lignes IPC mais une par (set, timeout) — les RR d'un même
-- RRset partagent leur TTL, le cas courant est donc une seule ligne pour le set
-- de la règle et une pour le set MAC (cf. nft_queue.add_many et
-- docs/agents/perf.md §29a).
-- @tparam table answers Liste normalisée de { family:"ipv4"|"ipv6", addr, ttl }.
-- @tparam table opts {
--   client_addr  : (family) -> addr|nil   résout l'adresse client dans la famille
--   client_mac   : string
--   user         : string|nil
--   rule_id      : string
--   wildcard_ids : table (rule_id wildcard)
--   ack_corr     : string
--   inject_nft   : boolean                 si faux, aucune insertion (no-op comptable)
--   timeout_of   : (ttl) -> string         défaut rr_timeout
--   mac_valid    : (mac) -> boolean
--   add_ip       : { ipv4 = add_ip4_many, ipv6 = add_ip6_many }
--   add_mac      : { ipv4 = add_mac4_many, ipv6 = add_mac6_many }
-- }
-- @treturn table { records_to_add, success_any, ip_count, no_v4, no_v6 }
inject = (answers, opts) ->
  records_to_add = 0
  success_any    = false
  ip_count       = 0
  no_v4          = {}
  no_v6          = {}
  return { :records_to_add, :success_any, :ip_count, :no_v4, :no_v6 } unless opts.inject_nft

  timeout_of  = opts.timeout_of or rr_timeout
  mac_valid   = opts.mac_valid
  use_wild    = opts.user and opts.wildcard_ids and #opts.wildcard_ids > 0
  mac_ok      = mac_valid opts.client_mac

  -- Accumulateur d'insertions : une entrée par (fonction d'ajout, règle, clé
  -- client, timeout). `order` fixe l'ordre d'émission (`pairs` n'en garantit
  -- aucun) ; le nombre d'entrées est celui des sets touchés, donc le parcours
  -- linéaire reste court.
  groups = {}
  order  = {}
  add_addr = (add_fn, rule_id, key, addr, timeout) ->
    for g in *order
      if g.add_fn == add_fn and g.rule_id == rule_id and g.key == key and g.timeout == timeout
        g.addrs[#g.addrs + 1] = addr
        return
    order[#order + 1] = { :add_fn, :rule_id, :key, :timeout, addrs: { addr } }
    nil

  for ans in *answers
    fam     = ans.family
    add_ip  = opts.add_ip[fam]
    add_mac = opts.add_mac[fam]
    client  = opts.client_addr fam
    timeout = timeout_of ans.ttl

    if client
      records_to_add += 1
      add_addr add_ip, opts.rule_id, client, ans.addr, timeout
      -- L'injection wildcard est TOUJOURS tentée (set distinct de la règle).
      if use_wild
        for rid in *opts.wildcard_ids
          add_addr add_ip, rid, client, ans.addr, timeout
    else
      tbl = fam == "ipv4" and no_v4 or no_v6
      tbl[#tbl + 1] = ans.addr

    if mac_ok
      add_addr add_mac, opts.rule_id, opts.client_mac, ans.addr, timeout
      if use_wild
        for rid in *opts.wildcard_ids
          add_addr add_mac, rid, opts.client_mac, ans.addr, timeout

  for g in *order
    n = g.add_fn g.key, g.addrs, g.rule_id, g.timeout, opts.ack_corr
    if n and n > 0
      success_any = true
      -- `ip_count` ne compte, comme avant, que les adresses insérées dans le
      -- set IP de la règle de la réponse (ni wildcard, ni MAC).
      if g.rule_id == opts.rule_id and (g.add_fn == opts.add_ip.ipv4 or g.add_fn == opts.add_ip.ipv6)
        ip_count += n

  { :records_to_add, :success_any, :ip_count, :no_v4, :no_v6 }

{ :rr_timeout, :detect_wildcards, :inject }
