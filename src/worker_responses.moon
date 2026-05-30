-- src/worker_responses.moon
-- Worker response : traitement des réponses DNS (UDP/53 dst=LAN, src=resolver).
--
-- Pour chaque paquet :
--   1. Draine le pipe IPC (absorbe les tokens question → table pending)
--   2. Parse L3/L4/L7 via parse/packet (IPv4 et IPv6)
--   3. Vérifie que la transaction (txid, dst_ip, dst_port) est dans pending
--   4. Si refusée (entry.refused = true) :
--        a. Remplace le payload DNS par une réponse REFUSED+EDE (Filtered)
--        b. Renvoie le paquet transformé au client
--   5. Si autorisée (entry.refused = false) :
--        a. Parse les RR DNS de la réponse
--        b. Conserve le payload tel quel sauf modification explicite (ex: strip HTTPS/SVCB)
--        c. Ajoute EDE uniquement si la réponse est effectivement modifiée
--        d. Recalcule checksums UDP/TCP et IP
--        e. Ajoute les IPs A/AAAA dans les sets nft (timeout = TTL RR + grace, borné)
--        f. Envoie le paquet modifié avec NF_ACCEPT + payload

{ :ffi, :libc, :libnfq } = require "ffi_defs"
config = require "config"
runtime_cfg = config.runtime or {}
ipc_cfg = config.ipc or {}
match_retry_cfg = ipc_cfg.match_retry or {}
dns_cfg = config.dns or {}
ttl_cfg = dns_cfg.ttl_grace or {}
auth_cfg = config.auth or {}
clients_cfg = config.clients or {}
{ :user_for_mac } = require "auth.sessions"
{ parse: parse_ip4 }                     = require "ipparse.l3.ip4"
{ parse: parse_ip6 }                     = require "ipparse.l3.ip6"
{ parse: parse_udp }                     = require "ipparse.l4.udp"
{ parse: parse_tcp }                     = require "ipparse.l4.tcp"
{ parse: parse_dns, types: QTYPE }       = require "ipparse.l7.dns"
{ :ip2s }                                = require "ipparse.l3.ip"
{ new: new_stream }                      = require "ipparse.l4.tcp_stream"
{ :get_l2 } = require "nfq/ethernet"
{ :drain_pipe, :is_pending, :get_pending_entry, :consume } = require "ipc"
{ :add_ip4, :add_ip6, :add_mac4, :add_mac6, :get_last_seq, :wait_ack, :drain_ack } = require "nft_queue"
{ :run_queue, :NF_ACCEPT, :NF_DROP } = require "nfq_loop"
{ :log_info, :log_warn, :log_debug, :now, :set_action_prefix } = require "log"
{ :build_blocked_response, :build_nxdomain_response, :strip_https_rr, :add_ede_modified, :clear_ad_bit } = require "dns_ede"
bit = require "bit"

-- ── Constantes L3/L4 ────────────────────────────────────────────

PROTO_UDP = 17
PROTO_TCP = 6

-- IPv6 extension headers table
IPV6_EXT_HDRS = {
  [0]:   true   -- Hop-by-Hop Options
  [43]:  true   -- Routing
  [44]:  true   -- Fragment
  [51]:  false  -- AH
  [60]:  true   -- Destination Options
  [135]: true   -- Mobility
  [139]: true   -- HIP
  [140]: true   -- Shim6
}

skip_ipv6_ext_hdrs = (p, len, first_nh) ->
  nh  = first_nh
  off = 40
  while IPV6_EXT_HDRS[nh] != nil
    return nil, nil if off + 2 > len
    next_nh  = p[off]
    ext_size = if nh == 51
      (p[off + 1] + 2) * 4
    else
      (p[off + 1] + 1) * 8
    return nil, nil if ext_size < 8 or off + ext_size > len
    off += ext_size
    nh   = next_nh
  nh, off

dns_tcp_complete = (buf) ->
  return false if #buf < 2
  #buf >= 2 + buf\byte(1) * 256 + buf\byte(2)

tcp_state = new_stream dns_tcp_complete

-- ── Fonctions de mutation FFI (byte-level, big-endian) ──────────

r16 = (p, o) ->
  bit.bor bit.lshift(p[o], 8), p[o + 1]

w32 = (p, o, v) ->
  p[o]   = bit.band bit.rshift(v, 24), 0xFF
  p[o+1] = bit.band bit.rshift(v, 16), 0xFF
  p[o+2] = bit.band bit.rshift(v,  8), 0xFF
  p[o+3] = bit.band v, 0xFF

w16 = (p, o, v) ->
  p[o]   = bit.band bit.rshift(v, 8), 0xFF
  p[o+1] = bit.band v, 0xFF

fix_ip4_cksum = (buf, ihl) ->
  buf[10] = 0
  buf[11] = 0
  sum = 0
  for i = 0, ihl - 1, 2
    sum += bit.bor bit.lshift(buf[i], 8), buf[i + 1]
  while bit.rshift(sum, 16) != 0
    sum = bit.band(sum, 0xFFFF) + bit.rshift(sum, 16)
  w16 buf, 10, bit.band(bit.bnot(sum), 0xFFFF)

fix_udp4_cksum = (buf, pkt_len, ihl) ->
  udp_off = ihl
  return if pkt_len < udp_off + 8
  udp_len = r16 buf, udp_off + 4
  buf[udp_off + 6] = 0
  buf[udp_off + 7] = 0
  sum = 0
  for i = 12, 18, 2
    sum += r16 buf, i
  sum += PROTO_UDP
  sum += udp_len
  udp_end = udp_off + udp_len
  udp_end = pkt_len if udp_end > pkt_len
  cksum_off = udp_off + 6
  i = udp_off
  while i < udp_end
    word = if i == cksum_off then 0
    elseif i + 1 < udp_end then r16 buf, i
    else bit.lshift buf[i], 8
    sum += word
    i += 2
  while bit.rshift(sum, 16) != 0
    sum = bit.band(sum, 0xFFFF) + bit.rshift(sum, 16)
  cksum = bit.band bit.bnot(sum), 0xFFFF
  cksum = 0xFFFF if cksum == 0
  w16 buf, udp_off + 6, cksum

fix_udp6_cksum = (buf, pkt_len, l4_off) ->
  udp_off = l4_off
  return if pkt_len < udp_off + 8
  udp_len = r16 buf, udp_off + 4
  buf[udp_off + 6] = 0
  buf[udp_off + 7] = 0
  sum = 0
  for i = 8, 38, 2
    sum += r16 buf, i
  sum += udp_len
  sum += PROTO_UDP
  udp_end = udp_off + udp_len
  udp_end = pkt_len if udp_end > pkt_len
  cksum_off = udp_off + 6
  i = udp_off
  while i < udp_end
    word = if i == cksum_off then 0
    elseif i + 1 < udp_end then r16 buf, i
    else bit.lshift buf[i], 8
    sum += word
    i += 2
  while bit.rshift(sum, 16) != 0
    sum = bit.band(sum, 0xFFFF) + bit.rshift(sum, 16)
  cksum = bit.band bit.bnot(sum), 0xFFFF
  cksum = 0xFFFF if cksum == 0
  w16 buf, udp_off + 6, cksum

fix_tcp4_cksum = (buf, pkt_len, ihl) ->
  tcp_off = ihl
  return if pkt_len < tcp_off + 20
  tcp_len = pkt_len - tcp_off
  buf[tcp_off + 16] = 0
  buf[tcp_off + 17] = 0
  sum = 0
  for i = 12, 18, 2
    sum += r16 buf, i
  sum += PROTO_TCP
  sum += tcp_len
  tcp_end = tcp_off + tcp_len
  tcp_end = pkt_len if tcp_end > pkt_len
  cksum_off = tcp_off + 16
  i = tcp_off
  while i < tcp_end
    word = if i == cksum_off then 0
    elseif i + 1 < tcp_end then r16 buf, i
    else bit.lshift buf[i], 8
    sum += word
    i += 2
  while bit.rshift(sum, 16) != 0
    sum = bit.band(sum, 0xFFFF) + bit.rshift(sum, 16)
  cksum = bit.band bit.bnot(sum), 0xFFFF
  cksum = 0xFFFF if cksum == 0
  w16 buf, tcp_off + 16, cksum

fix_tcp6_cksum = (buf, pkt_len, l4_off) ->
  tcp_off = l4_off
  return if pkt_len < tcp_off + 20
  tcp_len = pkt_len - tcp_off
  buf[tcp_off + 16] = 0
  buf[tcp_off + 17] = 0
  sum = 0
  for i = 8, 38, 2
    sum += r16 buf, i
  sum += tcp_len
  sum += PROTO_TCP
  tcp_end = tcp_off + tcp_len
  tcp_end = pkt_len if tcp_end > pkt_len
  cksum_off = tcp_off + 16
  i = tcp_off
  while i < tcp_end
    word = if i == cksum_off then 0
    elseif i + 1 < tcp_end then r16 buf, i
    else bit.lshift buf[i], 8
    sum += word
    i += 2
  while bit.rshift(sum, 16) != 0
    sum = bit.band(sum, 0xFFFF) + bit.rshift(sum, 16)
  cksum = bit.band bit.bnot(sum), 0xFFFF
  cksum = 0xFFFF if cksum == 0
  w16 buf, tcp_off + 16, cksum

-- Reconstruit un paquet IP avec un nouveau payload DNS.
-- ip_ihl : offset 0-based (en octets) de l'en-tête L4 depuis le début du paquet.
replace_dns_payload = (raw, ip, l4, ip_ihl, new_dns) ->
  p       = ffi.cast "const uint8_t*", raw
  dns_len = #new_dns

  if l4.proto == "udp"
    udp_len     = 8 + dns_len
    new_pkt_len = ip_ihl + udp_len
    new_buf = ffi.new "uint8_t[?]", new_pkt_len
    ffi.copy new_buf, p, ip_ihl + 8
    w16 new_buf, ip_ihl + 4, udp_len
    ffi.copy new_buf + ip_ihl + 8, new_dns, dns_len
    if ip.version == 4
      w16 new_buf, 2, new_pkt_len
      fix_udp4_cksum new_buf, new_pkt_len, ip_ihl
      fix_ip4_cksum  new_buf, ip_ihl
    elseif ip.version == 6
      w16 new_buf, 4, (ip_ihl - 40) + udp_len
      fix_udp6_cksum new_buf, new_pkt_len, ip_ihl
    return ffi.string new_buf, new_pkt_len

  elseif l4.proto == "tcp"
    tcp_hdr_len = bit.rshift(p[ip_ihl + 12], 4) * 4
    hdr_len     = ip_ihl + tcp_hdr_len
    new_pkt_len = hdr_len + 2 + dns_len
    new_buf = ffi.new "uint8_t[?]", new_pkt_len
    ffi.copy new_buf, p, hdr_len
    w16 new_buf, hdr_len, dns_len
    ffi.copy new_buf + hdr_len + 2, new_dns, dns_len
    w32 new_buf, ip_ihl + 4, l4.tcp_init_seq
    new_buf[ip_ihl + 13] = 0x18   -- PSH|ACK
    if ip.version == 4
      w16 new_buf, 2, new_pkt_len
      fix_tcp4_cksum new_buf, new_pkt_len, ip_ihl
      fix_ip4_cksum  new_buf, ip_ihl
    elseif ip.version == 6
      w16 new_buf, 4, (ip_ihl - 40) + tcp_hdr_len + 2 + dns_len
      fix_tcp6_cksum new_buf, new_pkt_len, ip_ihl
    return ffi.string new_buf, new_pkt_len

  nil

-- ── Parse answers depuis le dns_msg ipparse ──────────────────────

decode_simple_cname = (rdata) ->
  parts = {}
  pos = 1
  while pos <= #rdata
    len = rdata\byte pos
    break if len == 0
    return "(cname)" if bit.band(len, 0xC0) == 0xC0
    parts[#parts + 1] = rdata\sub pos+1, pos+len
    pos += 1 + len
  table.concat parts, "."

fmt_rdata = (rr) ->
  if (rr.rtype == 1 or rr.rtype == 28) and (#rr.rdata == 4 or #rr.rdata == 16)
    ip2s rr.rdata
  elseif rr.rtype == 5   -- CNAME
    decode_simple_cname rr.rdata
  else
    "(rdata #{#rr.rdata}B)"

parse_answers = (dns_msg) ->
  [ {
    name:       rr.name
    rtype:      rr.rtype
    rclass:     rr.rclass
    ttl:        rr.ttl
    rdlength:   #rr.rdata
    rdata_raw:  (rr.rtype == 1 or rr.rtype == 28) and rr.rdata or ""
    rdata_str:  fmt_rdata rr
    rtype_name: QTYPE[rr.rtype] or "TYPE#{rr.rtype}"
    ttl_offset: rr.off + #rr.rname + 3   -- 0-based depuis début du payload DNS (l7_off=1)
  } for rr in *dns_msg.answers ]

-- ── Parsing L3/L4/L7 ────────────────────────────────────────────

-- Extrait ip, l4, dns_msg, dns_raw, ip_ihl depuis un paquet IP brut.
-- Retourne nil, "status" sur les cas spéciaux.
-- ip_ihl est l'offset 0-based (octets) de L4 depuis le début du paquet.
parse_packet = (raw) ->
  ver = bit.rshift raw\byte(1), 4
  ip = if ver == 4
    ip4, _ = parse_ip4 raw
    ip4
  elseif ver == 6
    ip6, _ = parse_ip6 raw
    ip6
  return nil, "parse_failed" unless ip

  l4_off = ip.data_off
  proto  = ip.protocol or ip.next_header
  ip_ihl = ip.payload_off or (ip.data_off - 1)   -- offset 0-based de L4

  if ip.version == 6
    p = ffi.cast "const uint8_t*", raw
    proto, l4_off_0based = skip_ipv6_ext_hdrs p, #raw, ip.next_header
    return nil, "parse_failed" unless proto
    l4_off = l4_off_0based + 1
    ip_ihl = l4_off_0based

  if proto == PROTO_UDP
    udp, _ = parse_udp raw, l4_off
    return nil, "parse_failed" unless udp
    dns_raw = raw\sub udp.data_off, udp.off + udp.len - 1
    dns_msg, _ = parse_dns dns_raw, 1, false
    return nil, "parse_failed" unless dns_msg
    udp.proto = "udp"
    return ip, udp, dns_msg, dns_raw, ip_ihl

  elseif proto == PROTO_TCP
    tcp, _ = parse_tcp raw, l4_off
    return nil, "parse_failed" unless tcp
    payload = raw\sub tcp.data_off
    is_fin_rst = bit.band(tcp.flags, 0x05) != 0
    has_payload = payload != ""
    key = "#{ip2s ip.src}|#{tcp.spt}|#{ip2s ip.dst}|#{tcp.dpt}"
    buf, init_seq, first_seg = tcp_state.feed key, payload, tcp.flags, tcp.seq_n
    unless buf
      return nil, if is_fin_rst or not has_payload then "tcp_control" else "buffering"
    dns_raw = buf\sub 3
    dns_msg, _ = parse_dns dns_raw, 1, false
    return nil, "parse_failed" unless dns_msg
    tcp.proto = "tcp"
    tcp.tcp_init_seq = init_seq
    tcp.tcp_single_segment = first_seg
    tcp.tcp_dns_raw = dns_raw
    return ip, tcp, dns_msg, dns_raw, ip_ihl

  nil, "parse_failed"

-- ── Chargement paresseux de filter pour éviter de tirer ip_whitelist (libnftnl)
-- au chargement du module — critique pour les tests unitaires.
_filter = nil
run_on_response = (rule_id, dns_raw, reason) ->
  _filter or= require "filter"
  _filter.run_on_response rule_id, dns_raw, reason

-- Load filter rules to identify auth-only wildcard rules
-- rules_metadata is passed from main.moon to avoid recompiling (which would reload domain lists)
rules_metadata = nil

-- Cache of auth-only wildcard rules (requires_auth=true, #dns_refs==0)
auth_wildcard_rules = {}
load_auth_wildcard_rules = (metadata) ->
  rules_metadata = metadata
  auth_wildcard_rules = {}
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
      rule_id = meta.rule_id or "unknown_#{idx}"
      auth_wildcard_rules[#auth_wildcard_rules + 1] = rule_id
      log_info -> { action: "auth_wildcard_rule_detected", rule_id: rule_id, idx: idx }
  log_info -> { action: "auth_wildcard_rules_loaded", count: #auth_wildcard_rules, rules: table.concat(auth_wildcard_rules, ", ") }

add_to_wildcard_rules = (add_fn, key, dest, timeout, corr) ->
  any_ok = false
  for _, auth_rule_id in ipairs auth_wildcard_rules
    any_ok or= add_fn key, dest, auth_rule_id, timeout, corr
  any_ok

IPC_RETRY_ENABLED = if match_retry_cfg.enabled == nil then true else match_retry_cfg.enabled
IPC_RETRY_COUNT = match_retry_cfg.count or 5
IPC_RETRY_SLEEP_MS = match_retry_cfg.sleep_ms or 20

-- MAC_ZERO : MAC à ignorer (interface sans L2)
MAC_ZERO = "00:00:00:00:00:00"

-- mac_valid : vrai si mac est une adresse MAC connue et non nulle
mac_valid = (mac) -> mac != "unknown" and mac != MAC_ZERO


-- mac_clients[mac_str] = {ipv4, ipv6, last_seen}
-- Permet de résoudre l'adresse cross-family d'un client (ex: IPv4 ↔ IPv6)
mac_clients = {}

-- ip_to_mac[ip_str] = mac_str  (reverse lookup)
ip_to_mac = {}

-- fd de lecture du pipe IPC, injecté par main.moon avant fork()
pipe_rfd = nil

sleep_req = ffi.new "timespec_t[1]"
CLOCK_MONOTONIC = 1

-- Benchmark : buffer timespec réutilisé
_benchmark_ts = ffi.new "timespec_t[1]"

--- Retourne les millisecondes depuis boot (CLOCK_MONOTONIC).
-- @treturn number
current_benchmark_ms = ->
  libc.clock_gettime CLOCK_MONOTONIC, _benchmark_ts
  tonumber(_benchmark_ts[0].tv_sec) * 1000 + math.floor(tonumber(_benchmark_ts[0].tv_nsec) / 1000000)

update_mac_clients = nil
drain_ts = 0
drain_on_msg = (msg) ->
  update_mac_clients msg, drain_ts

sleep_ms = (ms) ->
  return unless ms and ms > 0
  sleep_req[0].tv_sec = math.floor ms / 1000
  sleep_req[0].tv_nsec = (ms % 1000) * 1000000
  libc.nanosleep sleep_req, nil

retry_pending_match = (txid, client_ip, client_port, resolver_ip) ->
  return nil, 0, 0 unless IPC_RETRY_ENABLED
  tries = IPC_RETRY_COUNT or 0
  wait_ms = IPC_RETRY_SLEEP_MS or 0
  return nil, 0, 0 if tries <= 0

  total_wait_ms = 0
  for i = 1, tries
    sleep_ms wait_ms
    total_wait_ms += wait_ms
    ts = now!
    drain_ts = ts
    drain_pipe pipe_rfd, now, drain_on_msg
    entry = get_pending_entry txid, client_ip, client_port, resolver_ip, now
    return entry, i, total_wait_ms if entry

  nil, tries, total_wait_ms

-- ── Suivi des clients par adresse MAC ───────────────────────────
-- Mise à jour de mac_clients et ip_to_mac à chaque message IPC reçu.
-- Appelé en callback depuis drain_pipe.
--- Met à jour l'association MAC → {ipv4|ipv6} depuis un message IPC décodé.
-- @tparam table  msg Message IPC décodé ({txid, ip_str, src_port, msg_type, mac_str})
-- @tparam number ts  Timestamp courant (secondes)
-- @treturn nil
update_mac_clients = (msg, ts) ->
  mac = msg.mac_str
  return if mac == MAC_ZERO   -- MAC inconnue : on ignore

  entry = mac_clients[mac] or {}
  entry.last_seen = ts

  if msg.ipv4   -- MSG_IPV4 ou MSG_IPV4_REFUSED
    unless entry.ipv4 == msg.ip_str
      ip_to_mac[entry.ipv4] = nil if entry.ipv4
      entry.ipv4 = msg.ip_str
      ip_to_mac[msg.ip_str] = mac
  else                        -- MSG_IPV6
    unless entry.ipv6 == msg.ip_str
      ip_to_mac[entry.ipv6] = nil if entry.ipv6
      entry.ipv6 = msg.ip_str
      ip_to_mac[msg.ip_str] = mac

  mac_clients[mac] = entry

--- Purge les entrées mac_clients inactives depuis plus de CLIENT_EXPIRY secondes.
-- Appelé périodiquement dans handle_response.
-- @tparam number ts Timestamp courant (secondes)
-- @treturn nil
purge_mac_clients = (ts) ->
  for mac, entry in pairs mac_clients
    if ts - entry.last_seen > (clients_cfg.expiry or 300)
      ip_to_mac[entry.ipv4] = nil if entry.ipv4
      ip_to_mac[entry.ipv6] = nil if entry.ipv6
      entry.ips = nil
      mac_clients[mac] = nil
      log_info -> { action: "client_expired", mac: mac }

--- Résout l'adresse IPv4 d'un client connu par son adresse IPv6 (ou vice-versa)
-- via la table mac_clients.
-- @tparam  string  ip_str Adresse IP du client connue
-- @tparam  string  want   "ipv4" ou "ipv6"
-- @treturn string|nil Adresse IP dans la famille demandée, ou nil si inconnue
resolve_client_family = (ip_str, want) ->
  mac = ip_to_mac[ip_str]
  if mac
    entry = mac_clients[mac]
    result = entry and entry[want]
    return result if result

  nil

clamp = (value, min_v, max_v) ->
  return min_v if value < min_v
  return max_v if value > max_v
  value

rr_timeout = (ttl) ->
  grace = math.max 0, math.floor(tonumber(ttl_cfg.grace) or 600)
  min_t = math.max 1, math.floor(tonumber(ttl_cfg.min) or 60)
  max_t = math.max min_t, math.floor(tonumber(ttl_cfg.max) or 2592000)

  rr_ttl = tonumber(ttl) or 0
  rr_ttl = math.floor rr_ttl
  rr_ttl = 0 if rr_ttl < 0
  effective = clamp rr_ttl + grace, min_t, max_t
  tostring(effective) .. "s", effective

patch_modified_dns = (dns_raw, reason) ->
  new_dns = strip_https_rr(dns_raw) or dns_raw
  payload_modified = new_dns != dns_raw
  
  -- If HTTPS/SVCB records were stripped, clear AD bit (signature is now invalid)
  if payload_modified
    new_dns = clear_ad_bit(new_dns)
    new_dns = add_ede_modified(new_dns, reason) or new_dns
  
  new_dns, payload_modified

--- Process a DNS response packet from NFQUEUE.
-- Drains IPC, validates the transaction, patches TTL+checksums,
-- injects resolved IPs into nftables, and sets the verdict.
-- @tparam cdata  qh_ptr  nfq_q_handle pointer (for nfq_set_verdict)
-- @tparam cdata  nfad    nfq_data pointer
-- @tparam number pkt_id  NFQUEUE packet id
-- @treturn number NF_ACCEPT, NF_DROP, or -1 (verdict already set)
handle_response = (qh_ptr, nfad, pkt_id) ->
  -- ── Drain pipe IPC ───────────────────────────────────────────
  -- Absorbe tous les tokens disponibles de question avant de traiter ce paquet.
  -- Le callback update_mac_clients enrichit la table mac_clients au passage.
  ts = now!
  drain_ts = ts
  drain_pipe pipe_rfd, now, drain_on_msg

  -- ── Payload brut ─────────────────────────────────────────────
  payload_ptr = ffi.new "unsigned char*[1]"
  payload_len = libnfq.nfq_get_payload nfad, payload_ptr
  if payload_len <= 0
    return NF_DROP

  raw = ffi.string payload_ptr[0], payload_len

  -- ── L2 ────────────────────────────────────────────────────
  -- MAC source via nfq_get_packet_hw() ; MAC destination non exposée par libnfq.
  l2 = get_l2 nfad

  -- ── L3 / L4 / L7 ───────────────────────────────────────────────
  -- parse_packet gère IPv4 et IPv6, UDP et TCP, et le header DNS en un seul appel.
  ip, l4, dns_msg, dns_raw, ip_ihl = parse_packet raw
  unless ip
    -- Intermediate TCP data segments are DROPped so response can reinject a single
    -- coalesced+TTL-patched packet once the full DNS message is assembled.
    -- TCP control packets (SYN-ACK, pure ACK with no payload, FIN) return nil
    -- without "buffering" and must be passed through unchanged.
    return NF_DROP if l4 == "buffering"
    return NF_ACCEPT

  -- Purge périodique sans math.random (hot-path): compteur mod 1000
  _purge_counter = ((_purge_counter or 0) + 1) % 1000
  if _purge_counter == 0
    tcp_state.purge!
    purge_mac_clients ts

  unless dns_msg.header.qr
    return NF_ACCEPT

  -- La question originale avait src_ip=ip.dst, src_port=l4.dpt
  -- (la réponse est adressée au client LAN).
  src_ip      = ip2s ip.src
  dst_ip      = ip2s ip.dst
  client_port = l4.dpt
  txid        = dns_msg.header.id
  client_ip   = dst_ip
  resolver_ip = src_ip
  -- MAC du client : resolution depuis la table ip_to_mac alimentée par question via IPC.
  -- mac_dst n'est jamais exposée par libnfq ; on utilise le reverse-lookup local.
  client_mac = ip_to_mac[client_ip] or "unknown"
  -- Utilisateur authentifié (nil si l'IP n'a pas de session valide)
  -- L'indexation par MAC permet de reconnaître un client authentifié
  -- en IPv6 quand ses paquets IPv4 arrivent (et vice-versa) de manière O(1).
  user        = user_for_mac client_mac, client_ip, auth_cfg.sessions_file or "/tmp/sessions.lua"

  -- ── Vérification IPC ─────────────────────────────────────────
  entry = get_pending_entry txid, dst_ip, client_port, resolver_ip, now
  unless entry
    retry_attempts = 0
    retry_wait_ms = 0
    entry, retry_attempts, retry_wait_ms = retry_pending_match txid, dst_ip, client_port, resolver_ip
    if entry
      log_info -> {
        action: "response_matched_after_retry"
        src_ip: src_ip
        dst_ip: dst_ip
        txid: string.format "0x%04x", txid
        retry_attempts: retry_attempts
        retry_wait_ms: retry_wait_ms
        user: user
      }
    else
      log_debug -> {
        action:    if retry_attempts > 0 then "response_no_matching_question_after_retry" else "response_no_matching_question"
        src_ip:    src_ip
        dst_ip:    dst_ip
        vlan:      l2.vlan
        txid:      string.format "0x%04x", txid
        rcode:     dns_msg.header.rcode
        client_mac: client_mac
        retry_attempts: retry_attempts
        retry_wait_ms: retry_wait_ms
        user: user
      }
      return NF_DROP
  -- Transaction consommée (one-shot : une réponse par question)
  consume txid, dst_ip, client_port, resolver_ip

  -- Benchmark : log le temps de traitement question → réponse
  if runtime_cfg.benchmark and entry and entry.benchmark_ms
    delta_ms = current_benchmark_ms! - entry.benchmark_ms
    if delta_ms >= 0
      log_info -> {
        action: "dns_benchmark"
        txid: string.format "0x%04x", txid
        src_ip: src_ip
        dst_ip: dst_ip
        delta_ms: delta_ms
        refused: entry.refused
        dnsonly: entry.dnsonly
        user: user
      }

  refused = entry and entry.refused or false
  dnsonly = entry and entry.dnsonly or false
  nft_rule_id = (entry and entry.rule_id and #entry.rule_id > 0) and entry.rule_id or "unknown_rule"
  ack_corr = string.format "%04x:%s:%d:%s", txid, dst_ip, client_port, resolver_ip

  -- ── Branche REFUSED/NXDOMAIN : réponse du serveur transformée ──────
  if refused
    nxdomain_mod = entry.modifiers and entry.modifiers.nxdomain
    refused_dns = if nxdomain_mod
      build_nxdomain_response dns_msg, dns_raw, entry.reason
    else
      build_blocked_response dns_msg, dns_raw, entry.reason
    unless refused_dns
      return NF_DROP
    refused_dns = strip_https_rr(refused_dns) or refused_dns
    patched = replace_dns_payload raw, ip, l4, ip_ihl, refused_dns
    unless patched
      return NF_DROP
    qnames = table.concat [q.name for q in *dns_msg.questions], ","
    log_debug -> {
      action:   nxdomain_mod and "response_nxdomain" or "response_refused"
      src_ip:   src_ip
      dst_ip:   dst_ip
      vlan:     l2.vlan
      txid:     string.format "0x%04x", txid
      qnames:   qnames
      client_mac: client_mac
      user:     user
    }
    patched_ptr = ffi.cast "const unsigned char*", patched
    libnfq.nfq_set_verdict qh_ptr, pkt_id, NF_ACCEPT, #patched, patched_ptr
    return -1

  -- ── Branche ACCEPT : callbacks on_response → injection nft ──────
  -- Dispatch factorisé (filter.run_on_response) : les callbacks de chaque
  -- action portent toute la logique (strip DNS, EDE, skip_nft, action_label)
  -- et la décision inject_nft. Même noyau que le worker DoH.
  resp_ctx = run_on_response nft_rule_id, dns_raw, (entry and entry.reason or "")

  dns_raw         = resp_ctx.dns_raw
  payload_modified = resp_ctx.modified
  inject_nft      = resp_ctx.inject_nft

  answers  = parse_answers dns_msg
  client_v4 = nil
  client_v6 = nil
  ip_count = 0
  records_to_add = 0
  success_any = false
  no_ipv4_records = {}
  no_ipv6_records = {}
  -- Purge stale ACKs before enqueueing new items so that wait_ack only
  -- consumes the ACK produced by the batch that actually contains our adds.
  drain_ack! if inject_nft and not dnsonly
  for ans in *answers
    if ans.rtype == QTYPE.A
      -- Enregistrement A : le client doit avoir une adresse IPv4
      client_v4 or= if ip.version == 4
        client_ip
      else
        -- DNS transporté en IPv6 : résoudre l'IPv4 via mac_clients
        resolve_client_family client_ip, "ipv4"
      if inject_nft
        if client_v4
          records_to_add += 1
          rr_timeout_str, _ = rr_timeout ans.ttl
          ok = add_ip4 client_v4, ans.rdata_str, nft_rule_id, rr_timeout_str, ack_corr
          ip_count += 1 if ok
          success_any or= ok
          if user and #auth_wildcard_rules > 0
            success_any or= add_to_wildcard_rules add_ip4, client_v4, ans.rdata_str, rr_timeout_str, ack_corr
        else
          no_ipv4_records[#no_ipv4_records + 1] = ans.rdata_str
        if mac_valid client_mac
          rr_timeout_str, _ = rr_timeout ans.ttl
          m_ok = add_mac4 client_mac, ans.rdata_str, nft_rule_id, rr_timeout_str, ack_corr
          success_any or= m_ok
          if user and #auth_wildcard_rules > 0
            success_any or= add_to_wildcard_rules add_mac4, client_mac, ans.rdata_str, rr_timeout_str, ack_corr
    elseif ans.rtype == QTYPE.AAAA
      -- Enregistrement AAAA : le client doit avoir une adresse IPv6
      client_v6 or= if ip.version == 6
        client_ip
      else
        -- DNS transporté en IPv4 : résoudre l'IPv6 via mac_clients
        resolve_client_family client_ip, "ipv6"
      if inject_nft
        if client_v6
          records_to_add += 1
          rr_timeout_str, _ = rr_timeout ans.ttl
          ok = add_ip6 client_v6, ans.rdata_str, nft_rule_id, rr_timeout_str, ack_corr
          ip_count += 1 if ok
          success_any or= ok
          if user and #auth_wildcard_rules > 0
            success_any or= add_to_wildcard_rules add_ip6, client_v6, ans.rdata_str, rr_timeout_str, ack_corr
        else
          no_ipv6_records[#no_ipv6_records + 1] = ans.rdata_str
        if mac_valid client_mac
          rr_timeout_str, _ = rr_timeout ans.ttl
          m_ok = add_mac6 client_mac, ans.rdata_str, nft_rule_id, rr_timeout_str, ack_corr
          success_any or= m_ok
          if user and #auth_wildcard_rules > 0
            success_any or= add_to_wildcard_rules add_mac6, client_mac, ans.rdata_str, rr_timeout_str, ack_corr

  -- Logguer les cas cross-family sans IP connue (groupés par réponse)
  if #no_ipv4_records > 0
    log_fn = if mac_valid(client_mac) then log_info else log_warn
    log_fn -> { action: "no_ipv4_for_client", client: client_ip, count: #no_ipv4_records,
          records: table.concat(no_ipv4_records, " "),
          reason: "client_ipv4_unknown", mac_fallback: mac_valid(client_mac), user: user }
  if #no_ipv6_records > 0
    log_fn = if mac_valid(client_mac) then log_info else log_warn
    log_fn -> { action: "no_ipv6_for_client", client: client_ip, count: #no_ipv6_records,
          records: table.concat(no_ipv6_records, " "),
          reason: "client_ipv6_unknown", mac_fallback: mac_valid(client_mac), user: user }

  -- ── Patch TTL + HTTPS/SVCB (toujours appliqué) ─────────────────
  new_dns, dns_modified = patch_modified_dns dns_raw, entry.reason
  payload_modified = payload_modified or dns_modified
  patched = nil
  if payload_modified
    patched = replace_dns_payload raw, ip, l4, ip_ihl, new_dns
    return NF_DROP unless patched

  -- Log de la réponse (lazy pour éviter construction si DEBUG filtré)
  qnames = table.concat [q.name for q in *dns_msg.questions], ","
  log_debug -> {
    action:      resp_ctx.action_label or (payload_modified and "response_patched" or "response_allow")
    src_ip:      src_ip
    dst_ip:      dst_ip
    vlan:        l2.vlan
    txid:        string.format "0x%04x", txid
    qnames:      qnames
    answers:     ip_count
    nft_rule_id: nft_rule_id
    payload_modified: payload_modified
    rcode:       dns_msg.header.rcode
    client_mac:  client_mac
    user:        user
  }

  -- If we had records to add but none succeeded, respect policy
  if records_to_add > 0 and not success_any
    if ((config.nft or {}).add_failure_policy or "fail-closed") == "fail-closed"
      log_debug -> { action: "nft_add_failed_policy_fail_closed", txid: string.format("0x%04x", txid), client_ip: client_ip, qnames: qnames, user: user }
      return NF_DROP
    else
      log_warn -> { action: "nft_add_failed_fail_open", txid: string.format("0x%04x", txid), client_ip: client_ip, qnames: qnames, user: user }

  -- ── Attente ACK nft avant verdict ────────────────────────────
  -- On attend que worker_nft confirme l'insertion des IPs dans les sets nftables
  -- avant de rendre la réponse DNS au client. Cela élimine la race condition
  -- où le client reçoit la réponse DNS et tente immédiatement une connexion TCP
  -- avant que ses IPs ne soient dans les sets par règle.
  -- Fail-open (avec log) si worker_nft ne répond pas dans NFT_ACK_TIMEOUT_MS.
  if not dnsonly and records_to_add > 0
    pending_seq = get_last_seq!
    wait_ack pending_seq, ack_corr if pending_seq

  -- ── Verdict ──────────────────────────────────────────────────
  -- Si payload inchangé : laisser passer le paquet original (pas d'altération DNS).
  return NF_ACCEPT unless payload_modified

  -- Payload modifié : verdict explicite avec paquet reconstruit.
  patched_ptr = ffi.cast "const unsigned char*", patched
  libnfq.nfq_set_verdict qh_ptr, pkt_id, NF_ACCEPT, #patched, patched_ptr
  -1   -- sentinel : verdict déjà posé, nfq_loop ne doit pas reposer de verdict


-- ── Point d'entrée ───────────────────────────────────────────────
--- Start the response worker.
-- Blocks in the NFQUEUE loop until the process exits.
-- @tparam number rfd Read end of the IPC pipe from question.
-- @tparam table rules_metadata Rules metadata passed from main.moon to avoid recompiling
run = (queue_num, rfd, rules_metadata) ->
  set_action_prefix "response_"
  load_auth_wildcard_rules rules_metadata if rules_metadata
  if type(rfd) == "table"
    nft_q = require "nft_queue"
    nft_q.set_wfd rfd.nft_wfd if rfd.nft_wfd
    -- Configure le canal ACK bidirectionnel si le superviseur en a alloué un.
    nft_q.set_ack_rfd rfd.ack_rfd, rfd.worker_idx if rfd.ack_rfd and rfd.worker_idx != nil
    rfd = rfd.question_response_rfd
  pipe_rfd = rfd
  -- Pré-remplit mac_clients / ip_to_mac depuis la table ARP/NDP courante,
  -- avant même la première requête DNS. Indispensable pour le cross-family
  -- (IPv6 client → RR A) quand aucun message IPC n'a encore été reçu.
  -- mac_clients et ip_to_mac démarrent vides ; ils sont alimentés organiquement
  -- par les messages IPC reçus de question (update_mac_clients dans drain_on_msg).
  run_queue tonumber(queue_num), handle_response

{ :run, :rr_timeout, :patch_modified_dns }
