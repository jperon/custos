-- src/doh/validator.moon
-- Second avis synchrone pour le worker DoH : interroge un résolveur validateur
-- et retourne si le domaine est bloqué (NXDOMAIN ou REFUSED).
-- Supporte deux types d'endpoints par entrée dans la liste :
--   • IP (ex. "1.1.1.1") → UDP/53 via doh.upstream
--   • URL (ex. "https://1.1.1.1/dns-query") → DoH via doh.upstream_doh

upstream_mod = require "doh.upstream"
{ :parse }   = require "ipparse.l7.dns"
dns_classify = require "dns_classify"
{ :log_debug, :log_warn } = require "log"

RCODE_REFUSED = 5

-- Traduit un résultat dns_classify en override (même mapping que
-- worker_responses.make_override) pour application par doh.query.
verdict_to_override = (vi) ->
  switch vi.verdict
    when "block"
      { kind: "block" }
    when "sinkhole"
      { kind: "sinkhole", a: vi.a, aaaa: vi.aaaa, ttl: vi.ttl }
    when "redirect"
      { kind: "redirect", cname_target: vi.cname_target, a: vi.a, aaaa: vi.aaaa, ttl: vi.ttl }
    else
      nil

-- Chargement paresseux pour éviter la dépendance libcurl au démarrage
-- si aucun validate_resolver https:// n'est configuré.
upstream_curl_mod = nil
get_doh_mod = ->
  upstream_curl_mod or= require "doh.upstream_doh_curl"
  upstream_curl_mod

-- Sélectionne le module de transport et ouvre la connexion selon le type d'endpoint.
-- @tparam string endpoint  IP ou URL "https://...".
-- @tparam number timeout_ms
-- @treturn table|nil client, string|nil err
open_client = (endpoint, timeout_ms) ->
  if endpoint\sub(1, 8) == "https://"
    get_doh_mod!.new_client endpoint, timeout_ms
  else
    upstream_mod.new_client endpoint, 53, timeout_ms

-- Ferme le client selon son type (DoH ou UDP).
close_client = (client) ->
  if client._mod
    client._mod.close client
  else
    upstream_mod.close client

-- Interroge un endpoint et retourne les octets DNS bruts de la réponse.
do_query = (client, dns_raw) ->
  if client._mod
    client._mod.query client, dns_raw
  else
    upstream_mod.query client, dns_raw

--- Interroge les endpoints validateurs dans l'ordre et retourne l'override
-- classifié de la première réponse exploitable. Fail-open (nil) si tous les
-- endpoints sont injoignables ou muets.
-- @tparam string dns_raw        Requête DNS brute (wire format).
-- @tparam table  resolvers      Liste d'endpoints : IPs (UDP/53) ou URLs (DoH https://).
-- @tparam number timeout_ms     Délai UDP par endpoint en ms (défaut 1000).
-- @tparam number doh_timeout_ms Délai DoH par endpoint en ms (défaut 3000).
-- @treturn table|nil override { kind = "block"|"sinkhole"|"redirect", … } ou nil (pass / fail-open).
-- @treturn string|nil  Raison lisible (endpoint) si override, nil sinon.
query_classified = (dns_raw, resolvers, timeout_ms=1000, doh_timeout_ms=3000) ->
  for endpoint in *resolvers
    is_doh = endpoint\sub(1, 8) == "https://"
    t_ms   = is_doh and doh_timeout_ms or timeout_ms
    client, c_err = open_client endpoint, t_ms
    unless client
      log_warn -> { action: "validator_connect_failed", resolver_ip: endpoint, err: c_err }
      continue
    resp_raw, q_err = do_query client, dns_raw
    close_client client
    unless resp_raw
      log_warn -> { action: "validator_query_failed", resolver_ip: endpoint, err: q_err }
      continue
    resp_dns = parse resp_raw, 1, false
    unless resp_dns
      log_warn -> { action: "validator_parse_failed", resolver_ip: endpoint }
      continue
    -- REFUSED : signal de blocage générique du validateur, non couvert par
    -- dns_classify (qui ne traite que NXDOMAIN/sinkhole/CNAME) → block explicite.
    if dns_classify.numeric_rcode(resp_dns.header) == RCODE_REFUSED
      log_debug -> { action: "validator_verdict", resolver_ip: endpoint, verdict: "block_refused" }
      return { kind: "block" }, "validator=#{endpoint} rcode=REFUSED"
    vi = dns_classify.classify resp_dns, resp_raw
    log_debug -> { action: "validator_verdict", resolver_ip: endpoint, verdict: vi.verdict }
    override = verdict_to_override vi
    return override, (override and "validator=#{endpoint} verdict=#{vi.verdict}" or nil)
  log_warn -> { action: "validator_all_failed", count: #resolvers }
  nil, nil

--- Variante booléenne historique : true si la première réponse exploitable est
-- un blocage (block / sinkhole / redirect). Fail-open si tous muets.
-- @treturn boolean blocked, string|nil reason
query_verdict = (dns_raw, resolvers, timeout_ms=1000, doh_timeout_ms=3000) ->
  override, reason = query_classified dns_raw, resolvers, timeout_ms, doh_timeout_ms
  (override != nil), reason

{ :query_verdict, :query_classified }
