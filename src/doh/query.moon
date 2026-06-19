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
{ :build_blocked_response, :build_nxdomain_response, :build_sinkhole_response, :build_cname_response, :build_captive_response, :add_ede, :patch_modified_dns } = require "dns_ede"
{ :inject, :detect_wildcards } = require "response_inject"
{ :user_for_mac } = require "auth.sessions"
{ :log_allow, :log_block, :log_warn, :log_debug, :log_info } = require "log"
{ :ip2s } = require "lib.packet_parsing"
config = require "config"
upstream_mod = require "doh.upstream"
{ :query_classified } = require "doh.validator"

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

-- Domaine et IP du portail captif (vol DNS DoH, miroir de worker_questions).
-- Renseignés par worker_doh au démarrage / reload via set_captive.
captive_domain = nil
captive_ip4    = nil
captive_ip6    = nil

--- Déclare le hostname et les IP du portail captif pour le vol DNS DoH.
-- @tparam string|nil domain Hostname du portail captif (casse basse), ou nil.
-- @tparam string|nil ip4    Adresse IPv4 du portail captif, ou nil.
-- @tparam string|nil ip6    Adresse IPv6 du portail captif, ou nil.
set_captive = (domain, ip4, ip6) ->
  captive_domain = domain
  captive_ip4    = ip4
  captive_ip6    = ip6
  log_info -> { action: "doh_captive_loaded", domain: domain or "none", ip4: ip4 or "none", ip6: ip6 or "none" }

QTYPE_A    = QTYPE.A
QTYPE_AAAA = QTYPE.AAAA

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
-- @tparam number|nil   client_vlan VLAN ID observé pour l'IP (0 = untagged, nil = inconnu).
-- @treturn string|nil dns_resp    Raw DNS response bytes to send back, or nil.
-- @treturn string|nil err         Error string if nil is returned.
process_query = (dns_raw, client_ip, client_mac, upstream, client_vlan) ->
  dns, parse_err = parse dns_raw, 1, false
  unless dns
    log_warn -> { action: "parse_failed", client_ip: client_ip, err: tostring parse_err }
    return nil, "dns_parse_failed"

  -- ── Vol de question DNS pour le portail captif (miroir worker_questions) ──
  -- Si la question porte sur le hostname du portail (A/AAAA), répondre avec
  -- l'IP locale du boîtier sans filtrer ni remonter l'upstream. Indispensable à
  -- la parité UDP/DoH : sinon le client DoH résout le vrai nom public.
  if captive_domain
    for q in *(dns.questions or (dns.question and { dns.question } or {}))
      norm = (q.name or q.qname or "")\lower!\gsub "%.+$", ""
      if norm == captive_domain and (q.qtype == QTYPE_A or q.qtype == QTYPE_AAAA)
        forged = build_captive_response dns, dns_raw, captive_ip4, captive_ip6
        if forged
          log_info -> { action: "dns_stolen", worker: "doh", domain: q.name or q.qname, qtype: q.qtype_name or tostring(q.qtype), client_ip: client_ip, client_mac: client_mac }
          return forged
        log_warn -> { action: "dns_steal_forge_failed", worker: "doh", domain: q.name or q.qname, client_ip: client_ip }

  user = user_for_mac client_mac, client_ip, config.auth.sessions_file
  log_debug -> { action: "process_query", client_ip: client_ip, client_mac: client_mac, user: user, query_bytes: #dns_raw }

  -- Evaluate all questions; block if any is refused.
  block_reason = nil
  allow_reason = nil
  blocked_dns  = nil
  any_blocked  = false
  allow_rule_id = nil
  allow_timeout = nil
  allow_response_rule_ids = {}
  allow_modifiers = {}

  questions = dns.questions or (dns.question and { dns.question } or {})
  for q in *questions
    qname_text = q.name or q.qname
    -- Parité sémantique UDP : untagged (0) → nil (from_vlan _none matche,
    -- from_vlan <id> ne matche pas). Le bénéfice anti-stale tient côté cache
    -- (l'entrée est rafraîchie à 0), pas via la valeur exposée ici.
    req = {
      domain: qname_text
      src_ip: client_ip
      mac:    client_mac
      vlan:   (client_vlan and client_vlan > 0) and client_vlan or nil
      ts:     os.time!
      user:   user
    }
    log_debug -> { action: "filter_decide", qname: qname_text, qtype: q.qtype_name or tostring(q.qtype), client_ip: client_ip }
    meta = decide_meta req
    fields = {
      action:  if meta.verdict then "allow" else "block"
      worker:  "doh"
      qname:   qname_text
      qtype:   q.qtype_name or tostring(q.qtype)
      src_ip:  client_ip
      mac_src: client_mac
      vlan:    (client_vlan and client_vlan > 0) and client_vlan or nil
      user:    user
      reason:  meta.reason or ""
      rule:    meta.rule_id or ""
    }
    if meta.verdict
      log_allow -> fields
      allow_reason  = meta.reason
      allow_rule_id = meta.rule_id
      allow_timeout = meta.timeout
      allow_response_rule_ids = meta.response_rule_ids or {}
      allow_modifiers = meta.allow_modifiers or {}
    else
      log_block -> fields
      any_blocked  = true
      block_reason = meta.reason

  -- Second avis synchrone : si la règle porte l'action `validate` et que le
  -- filtre a autorisé la requête, interroger le résolveur validateur. On
  -- applique le verdict classifié (block / sinkhole / redirect) en miroir de
  -- worker_responses.finalize_a. Fail-open (pass) si tous injoignables.
  if not any_blocked and allow_modifiers.validate
    do_validate = allow_modifiers.validate
    val_resolvers = type(do_validate) == "table" and do_validate or (config.second_opinion or {}).resolvers or {}
    if #val_resolvers > 0
      so = config.second_opinion or {}
      timeout_ms     = so.budget_ms or 1000
      doh_timeout_ms = so.doh_budget_ms or 3000
      override, v_reason = query_classified dns_raw, val_resolvers, timeout_ms, doh_timeout_ms
      if override
        log_block -> { action: "doh_validator_override", kind: override.kind, src_ip: client_ip, mac_src: client_mac, vlan: (client_vlan and client_vlan > 0) and client_vlan or nil, user: user, reason: v_reason }
        switch override.kind
          when "block"
            return build_nxdomain_response(dns, dns_raw, v_reason) or build_blocked_response(dns, dns_raw, v_reason)
          when "sinkhole"
            sink = { a: override.a or {}, aaaa: override.aaaa or {}, ttl: override.ttl }
            return build_sinkhole_response(dns, dns_raw, v_reason, sink) or build_blocked_response(dns, dns_raw, v_reason)
          when "redirect"
            target_rrs = { a: override.a or {}, aaaa: override.aaaa or {}, ttl: override.ttl }
            new_dns = build_cname_response dns, dns_raw, override.cname_target, v_reason, target_rrs
            if new_dns
              -- Injecter les cibles du redirect en nft pour que le client les joigne.
              redirect_answers = {}
              for r in *(override.a or {})
                redirect_answers[#redirect_answers + 1] = { family: "ipv4", addr: ip2s(r), ttl: override.ttl }
              for r in *(override.aaaa or {})
                redirect_answers[#redirect_answers + 1] = { family: "ipv6", addr: ip2s(r), ttl: override.ttl }
              if #redirect_answers > 0
                is_v6 = (client_ip\find ":") ~= nil
                client_addr = (fam) ->
                  (fam == "ipv4" and not is_v6) and client_ip or
                  (fam == "ipv6" and is_v6) and client_ip or nil
                drain_ack!
                inject redirect_answers, {
                  :client_addr
                  :client_mac
                  :user
                  rule_id:    allow_rule_id or "unknown_rule"
                  :wildcard_ids
                  ack_corr:   string.format "%04x:%s", dns.txid or 0, client_ip or "unknown"
                  inject_nft: true
                  :mac_valid
                  add_ip:  { ipv4: add_ip4, ipv6: add_ip6 }
                  add_mac: { ipv4: add_mac4, ipv6: add_mac6 }
                }
                pending = get_last_seq!
                wait_ack pending, (string.format "%04x:%s", dns.txid or 0, client_ip or "unknown") if pending
              return new_dns
            return build_blocked_response(dns, dns_raw, v_reason)

  if any_blocked
    blocked = build_blocked_response dns, dns_raw, block_reason
    unless blocked
      log_warn -> { action: "blocked_build_failed", client_ip: client_ip, reason: block_reason }
      return nil, "blocked_response_build_failed"
    log_debug -> { action: "query_blocked", client_ip: client_ip, reason: block_reason }
    return blocked

  -- Forward to upstream DNS (plain UDP/53).
  resp_raw, upstream_err = ((upstream and upstream._mod) or upstream_mod).query upstream, dns_raw
  unless resp_raw
    log_warn -> { action: "upstream_failed", client_ip: client_ip, err: upstream_err }
    return nil, upstream_err or "upstream_failed"

  -- ── Dispatch on_response : même noyau que worker_responses ──────
  -- Les callbacks de chaque action portent toute la logique (strip DNS,
  -- EDE, skip_nft) et la décision inject_nft. "allow" supplante "skip".
  response_hooks = (#allow_response_rule_ids > 0) and allow_response_rule_ids or allow_rule_id
  resolver_ip_ctx = upstream and upstream.upstream_ip or nil
  resp_ctx = run_on_response response_hooks, resp_raw, allow_reason, { resolver_ip: resolver_ip_ctx }
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
    log_block -> { action: "doh_nft_add_failed_fail_closed", src_ip: client_ip, mac_src: client_mac, vlan: (client_vlan and client_vlan > 0) and client_vlan or nil, user: user, rule: allow_rule_id }
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

{ :process_query, :set_wildcard_rules, :set_captive, :normalize_answers }
