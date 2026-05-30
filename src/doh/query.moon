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
{ :decide_meta } = require "filter"
{ :add_ip4, :add_ip6, :add_mac4, :add_mac6, :get_last_seq, :wait_ack } = require "nft_queue"
{ :build_blocked_response, :add_ede } = require "dns_ede"
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

--- Inject A/AAAA records from a parsed DNS response into nftables sets,
-- then wait for worker_nft to confirm the flush before returning.
-- This prevents the race condition where the DoH response is sent to the client
-- before the resolved IPs are present in the nftables sets.
-- @tparam table  answers    Array of parsed RR tables (from ipparse.l7.dns).
-- @tparam string client_ip  Peer IP address (IPv4 or IPv6 string).
-- @tparam string client_mac MAC address string, or "unknown".
-- @treturn nil
inject_answers = (answers, client_ip, client_mac, rule_id, timeout, ack_corr) ->
  rule_id = rule_id or "unknown_rule"
  timeout = timeout or config.nft.ip_timeout
  is_v6_client = (client_ip\find ":") ~= nil
  for ans in *answers
    addr = rr_addr ans
    continue unless addr and addr != ""
    if ans.rtype == QTYPE.A
      unless is_v6_client
        log_debug -> { action: "nft_add_ip4", client_ip: client_ip, dest: addr }
        add_ip4 client_ip, addr, rule_id, timeout, ack_corr
      if mac_valid client_mac
        log_debug -> { action: "nft_add_mac4", client_mac: client_mac, dest: addr }
        add_mac4 client_mac, addr, rule_id, timeout, ack_corr
    elseif ans.rtype == QTYPE.AAAA
      if is_v6_client
        log_debug -> { action: "nft_add_ip6", client_ip: client_ip, dest: addr }
        add_ip6 client_ip, addr, rule_id, timeout, ack_corr
      if mac_valid client_mac
        log_debug -> { action: "nft_add_mac6", client_mac: client_mac, dest: addr }
        add_mac6 client_mac, addr, rule_id, timeout, ack_corr
  -- Attendre que worker_nft ait effectivement inséré les IPs dans nftables
  -- avant de retourner la réponse DNS au client DoH.
  -- Fail-open (avec log) si worker_nft ne répond pas dans NFT_ACK_TIMEOUT_MS.
  pending_seq = get_last_seq!
  wait_ack pending_seq, ack_corr if pending_seq

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

  -- Parse the response and inject A/AAAA records into nftables sets.
  resp_dns, resp_err = parse resp_raw, 1, false
  if resp_dns
    answers = resp_dns.answers or {}
    ack_corr = string.format "%04x:%s", dns.txid or 0, client_ip or "unknown"
    inject_answers answers, client_ip, client_mac, allow_rule_id, allow_timeout, ack_corr
    log_debug -> {
      action:     "query_allowed"
      client_ip:  client_ip
      client_mac: client_mac
      user:       user
      answers:    #answers
      reason:     allow_reason or ""
    }
  else
    log_warn -> { action: "response_parse_failed", client_ip: client_ip, err: tostring(resp_err) or "unknown" }

  resp_raw

{ :process_query }
