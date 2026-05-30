-- src/doh/query.moon
-- Core DoH query processing: filter, upstream DNS, nft injection.
--
-- Flow for each incoming DNS payload:
--   1. Parse questions via ipparse.l7.dns.
--   2. For each question, call filter.decide() (same logic as worker_questions).
--   3. If any question is blocked: return a REFUSED+EDE response (no upstream call).
--   4. Otherwise: forward raw DNS bytes to upstream via doh/upstream.
--   5. Parse A/AAAA answers in the response, inject into nft sets.
--   6. Return the raw upstream response to the caller.

dns_mod = require "ipparse.l7.dns"
parse = dns_mod.parse
{ types: QTYPE } = require "ipparse.l7.dns"
{ :decide_meta, :run_on_response } = require "filter"
{ :add_ip4, :add_ip6, :add_mac4, :add_mac6, :get_last_seq, :wait_ack, :drain_ack } = require "nft_queue"
{ :build_blocked_response, :add_ede, :patch_modified_dns } = require "dns_ede"
{ :inject, :detect_wildcards } = require "response_inject"
{ :user_for_mac } = require "auth.sessions"
{ :log_allow, :log_block, :log_warn, :log_debug, :log_info } = require "log"
config = require "config"
upstream_mod = require "doh.upstream"

MAC_ZERO = "00:00:00:00:00:00"
mac_valid = (mac) -> mac and mac != "unknown" and mac != MAC_ZERO

rr_addr = (ans) ->
  if ans.rtype == QTYPE.A and ans.rdata and #ans.rdata == 4
    return "#{ans.rdata\byte(1)}.#{ans.rdata\byte(2)}.#{ans.rdata\byte(3)}.#{ans.rdata\byte(4)}"
  if ans.rtype == QTYPE.AAAA and ans.rdata and #ans.rdata == 16
    words = {}
    for i = 1, 16, 2
      words[#words + 1] = string.format "%x", ans.rdata\byte(i) * 256 + ans.rdata\byte(i + 1)
    return table.concat words, ":"
  ans.rdata_str

-- Règles wildcard d'auth (cf. response_inject.detect_wildcards), renseignées
-- par worker_doh au démarrage / reload via set_wildcard_rules.
wildcard_ids = {}

--- Déclare les métadonnées de règles pour la détection des règles wildcard.
-- @tparam table rules_metadata Métadonnées compilées (filter rules).
set_wildcard_rules = (rules_metadata) ->
  wildcard_ids = detect_wildcards rules_metadata
  log_info -> { action: "doh_auth_wildcard_rules_loaded", count: #wildcard_ids, rules: table.concat(wildcard_ids, ", ") }

--- Normalise les réponses A/AAAA d'un message DNS parsé pour le noyau d'injection.
-- @tparam table resp_dns Message DNS parsé (ipparse.l7.dns).
-- @treturn table Liste de { family, addr, ttl }.
normalize_answers = (resp_dns) ->
  out = {}
  for ans in *(resp_dns.answers or {})
    continue unless ans.rtype == QTYPE.A or ans.rtype == QTYPE.AAAA
    addr = rr_addr ans
    continue unless addr and addr != ""
    out[#out + 1] = { family: (ans.rtype == QTYPE.AAAA and "ipv6" or "ipv4"), addr: addr, ttl: ans.ttl }
  out

--- Process a raw DNS query from a DoH client.
-- @tparam string      dns_raw     Raw DNS query bytes (wire format).
-- @tparam string      client_ip   Peer IP address string.
-- @tparam string      client_mac  MAC address string (or "unknown").
-- @tparam table       upstream    Client handle from doh.upstream.new_client().
-- @treturn string|nil dns_resp    Raw DNS response bytes to send back, or nil.
-- @treturn string|nil err         Error string if nil is returned.
process_query = (dns_raw, client_ip, client_mac, upstream) ->
  dns, parse_err = parse dns_raw, 1, false
  unless dns
    log_warn -> { action: "parse_failed", client_ip: client_ip, err: tostring parse_err }
    return nil, "dns_parse_failed"

  user = user_for_mac client_mac, client_ip, config.auth.sessions_file
  log_debug -> { action: "process_query", client_ip: client_ip, client_mac: client_mac, user: user, query_bytes: #dns_raw }

  -- Evaluate all questions; block if any is refused.
  block_reason = nil
  allow_reason = nil
  blocked_dns  = nil
  any_blocked  = false
  allow_rule_id = nil
  allow_timeout = nil

  questions = dns.questions or (dns.question and { dns.question } or {})
  for q in *questions
    qname_text = q.name or q.qname
    req = {
      domain: qname_text
      src_ip: client_ip
      mac:    client_mac
      ts:     os.time!
      user:   user
    }
    log_debug -> { action: "filter_decide", qname: qname_text, qtype: q.qtype_name or tostring(q.qtype), client_ip: client_ip }
    meta = decide_meta req
    fields = {
      action:   if meta.verdict then "allow" else "block"
      worker:   "doh"
      qname:    qname_text
      qtype:    q.qtype_name or tostring(q.qtype)
      client_ip: client_ip
      client_mac: client_mac
      user:     user
      reason:   meta.reason or ""
      rule:     meta.description or ""
    }
    if meta.verdict
      log_allow -> fields
      allow_reason  = meta.reason
      allow_rule_id = meta.rule_id
      allow_timeout = meta.timeout
    else
      log_block -> fields
      any_blocked  = true
      block_reason = meta.reason

  if any_blocked
    blocked = build_blocked_response dns, dns_raw, block_reason
    unless blocked
      log_warn -> { action: "blocked_build_failed", client_ip: client_ip, reason: block_reason }
      return nil, "blocked_response_build_failed"
    log_debug -> { action: "query_blocked", client_ip: client_ip, reason: block_reason }
    return blocked

  -- Forward to upstream DNS (plain UDP/53).
  resp_raw, upstream_err = upstream_mod.query upstream, dns_raw
  unless resp_raw
    log_warn -> { action: "upstream_failed", client_ip: client_ip, err: upstream_err }
    return nil, upstream_err or "upstream_failed"

  -- ── Dispatch on_response : même noyau que worker_responses ──────
  -- Les callbacks de chaque action portent toute la logique (strip DNS,
  -- EDE, skip_nft) et la décision inject_nft. "allow" supplante "skip".
  resp_ctx = run_on_response allow_rule_id, resp_raw, allow_reason
  resp_raw = resp_ctx.dns_raw

  -- Parse the (possibly modified) response and inject A/AAAA records into nft sets.
  resp_dns, resp_err = parse resp_raw, 1, false
  unless resp_dns
    log_warn -> { action: "response_parse_failed", client_ip: client_ip, err: tostring(resp_err) or "unknown" }
    return resp_raw

  -- ── Injection nft : noyau partagé avec worker_responses ─────────
  -- Famille de la connexion DoH ; le cross-family est couvert par l'injection
  -- MAC. Les règles wildcard d'auth sont incluses (response_inject.inject).
  is_v6_client = (client_ip\find ":") ~= nil
  client_addr = (fam) ->
    (fam == "ipv4" and not is_v6_client) and client_ip or
    (fam == "ipv6" and is_v6_client) and client_ip or nil

  ack_corr = string.format "%04x:%s", dns.txid or 0, client_ip or "unknown"
  answers  = normalize_answers resp_dns

  drain_ack! if resp_ctx.inject_nft
  inj = inject answers, {
    :client_addr
    :client_mac
    :user
    rule_id:      allow_rule_id or "unknown_rule"
    :wildcard_ids
    :ack_corr
    inject_nft:   resp_ctx.inject_nft
    :mac_valid
    add_ip:  { ipv4: add_ip4, ipv6: add_ip6 }
    add_mac: { ipv4: add_mac4, ipv6: add_mac6 }
  }

  -- ── Fail-closed : injection demandée mais aucune insertion réussie ──
  -- Cohérent avec worker_responses : plutôt que de livrer des IP que le client
  -- ne pourra pas joindre (default deny), on renvoie une réponse REFUSED+EDE.
  failure_policy = (config.nft or {}).add_failure_policy or "fail-closed"
  if inj.records_to_add > 0 and not inj.success_any and failure_policy == "fail-closed"
    log_block -> { action: "doh_nft_add_failed_fail_closed", client_ip: client_ip, client_mac: client_mac, user: user, rule: allow_rule_id }
    blocked = build_blocked_response dns, dns_raw, "nft_insert_failed"
    return blocked or resp_raw

  -- ── Patch « toujours appliqué » (strip HTTPS/SVCB + clear AD + EDE) ──
  -- Même transformation que worker_responses : force la révélation du SNI et
  -- invalide proprement DNSSEC (bit AD effacé) quand on modifie la réponse.
  resp_raw, _ = patch_modified_dns resp_raw, allow_reason

  -- Attendre que worker_nft ait inséré les IPs avant de répondre au client DoH.
  if resp_ctx.inject_nft
    pending_seq = get_last_seq!
    wait_ack pending_seq, ack_corr if pending_seq

  log_debug -> {
    action:     resp_ctx.action_label or "query_allowed"
    client_ip:  client_ip
    client_mac: client_mac
    user:       user
    answers:    inj.ip_count
    inject_nft: resp_ctx.inject_nft
    modified:   resp_ctx.modified
    reason:     allow_reason or ""
  }
  resp_raw

{ :process_query, :set_wildcard_rules, :normalize_answers }
