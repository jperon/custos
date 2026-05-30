-- src/response_inject.moon
-- Noyau commun d'injection nft des réponses DNS, partagé par worker_responses
-- (plan de données NFQUEUE) et doh/query (proxy DoH).
--
-- Responsabilités factorisées :
--   - rr_timeout        : TTL du RR → timeout de set nft (borné + grace)
--   - detect_wildcards  : règles wildcard d'auth (from_users sans to_domain*)
--   - add_to_wildcards  : recopie (key→dest) dans les sets des règles wildcard
--   - inject            : boucle d'injection A/AAAA (per-rule + mac + wildcard),
--                         avec comptage records_to_add/success pour le fail-closed.
--
-- Le module ne tire AUCUNE dépendance nft directe : les fonctions d'ajout
-- (add_ip4/6, add_mac4/6) sont injectées via `opts`, ce qui le rend testable
-- unitairement sans libnftnl.

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

--- Injecte (key→dest) dans les sets de toutes les règles wildcard via add_fn.
-- @tparam function add_fn       Fonction d'ajout nft (add_ip4/6/add_mac4/6).
-- @tparam table    wildcard_ids Liste de rule_id wildcard.
-- @treturn boolean true si au moins une insertion a réussi.
add_to_wildcards = (add_fn, wildcard_ids, key, dest, timeout, corr) ->
  any_ok = false
  for _, rid in ipairs wildcard_ids or {}
    -- NB : effet de bord dissocié de l'accumulation — `any_ok or= add_fn …`
    -- court-circuiterait et sauterait les règles suivantes dès le 1er succès.
    ok = add_fn key, dest, rid, timeout, corr
    any_ok = any_ok or ok
  any_ok

--- Boucle d'injection nft des réponses A/AAAA (noyau commun).
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
--   add_ip       : { ipv4: add_ip4, ipv6: add_ip6 }
--   add_mac      : { ipv4: add_mac4, ipv6: add_mac6 }
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

  for ans in *answers
    fam     = ans.family
    add_ip  = opts.add_ip[fam]
    add_mac = opts.add_mac[fam]
    client  = opts.client_addr fam
    timeout = timeout_of ans.ttl

    if client
      records_to_add += 1
      ok = add_ip client, ans.addr, opts.rule_id, timeout, opts.ack_corr
      ip_count += 1 if ok
      success_any = success_any or ok
      -- L'injection wildcard est TOUJOURS tentée (effet de bord dissocié du OR).
      if use_wild
        w_ok = add_to_wildcards add_ip, opts.wildcard_ids, client, ans.addr, timeout, opts.ack_corr
        success_any = success_any or w_ok
    else
      tbl = fam == "ipv4" and no_v4 or no_v6
      tbl[#tbl + 1] = ans.addr

    if mac_ok
      m_ok = add_mac opts.client_mac, ans.addr, opts.rule_id, timeout, opts.ack_corr
      success_any = success_any or m_ok
      if use_wild
        wm_ok = add_to_wildcards add_mac, opts.wildcard_ids, opts.client_mac, ans.addr, timeout, opts.ack_corr
        success_any = success_any or wm_ok

  { :records_to_add, :success_any, :ip_count, :no_v4, :no_v6 }

{ :rr_timeout, :detect_wildcards, :add_to_wildcards, :inject }
