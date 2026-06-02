-- src/worker_questions.moon
-- Worker question : traitement des questions DNS (UDP/53 src=LAN, dst=resolver).
--
-- Pour chaque paquet :
--   1. Parse L2 (MAC src via nfq_get_packet_hw)
--   2. Parse L3/L4/L7 via parse/packet (IPv4 et IPv6)
--   3. Vérifie allowlist → décide allow ou refuse
--   4. Si autorisé : envoie write_msg (allowed) dans le pipe IPC vers response, NF_ACCEPT
--   5. Si refusé   : envoie write_refused_msg dans le pipe IPC vers response, NF_ACCEPT
--      response intercepte la réponse du serveur et la transforme en REFUSED+EDE
--   6. Log structuré TSV (champs: decision, qname, mac_src, src_ip, dst_ip, vlan, user, af, reason, rule)

{ :ffi, :libc, :libnfq } = require "ffi_defs"
config = require "config"
runtime_cfg = config.runtime or {}
nft_cfg = config.nft or {}
auth_cfg = config.auth or {}
metrics = require "metrics"
{ :get_l2 } = require "nfq/ethernet"
{ parse: parse_ip4 }                     = require "ipparse.l3.ip4"
{ parse: parse_ip6 }                     = require "ipparse.l3.ip6"
{ parse: parse_udp }                     = require "ipparse.l4.udp"
{ parse: parse_tcp }                     = require "ipparse.l4.tcp"
{ parse: parse_dns, types: dns_types }   = require "ipparse.l7.dns"
{ :ip2s }                                = require "ipparse.l3.ip"
{ new: new_stream }                      = require "ipparse.l4.tcp_stream"
bit                                      = require "bit"
filter                   = require "filter"
{ :write_msg, :write_refused_msg } = require "ipc"
{ :run_queue, :NF_ACCEPT, :NF_DROP } = require "nfq_loop"
{ :log_allow, :log_block, :log_warn, :log_debug, :log_info, :set_action_prefix } = require "log"
{ :user_for_mac } = require "auth.sessions"
forge_dns = require "forge_dns"
{ detect: detect_captive_ips } = require "captive_ips"
bridge_raw = require "bridge_raw"
{ new: new_eth, proto: {:IP4, :IP6} } = require "ipparse.l2.ethernet"

-- fd d'écriture du pipe IPC question→response, injecté par main.moon avant fork()
pipe_wfd = nil

-- fd d'écriture du pipe d'apprentissage question→mac_learner.
mac_learn_wfd = nil

-- Benchmark : buffer timespec réutilisé pour éviter l'allocation hot-path
_benchmark_ts = ffi.new "timespec_t[1]"
CLOCK_MONOTONIC = 1

--- Retourne les millisecondes depuis boot (CLOCK_MONOTONIC), ou nil.
-- @treturn number|nil
get_benchmark_ms = ->
  return nil unless runtime_cfg.benchmark
  libc.clock_gettime CLOCK_MONOTONIC, _benchmark_ts
  tonumber(_benchmark_ts[0].tv_sec) * 1000 + math.floor(tonumber(_benchmark_ts[0].tv_nsec) / 1000000)

events_wfd = nil  -- fd d'écriture du pipe vers worker_events (nil si désactivé)

-- ── Vol de question DNS pour le portail captif ───────────────────
-- Initialisés dans run() depuis filter.get_auth_cfg().
-- captive_domain : hostname en casse basse (ex. "custos.mon-routeur.lan"),
--                 nil si redirect_url absent ou contient une IP brute.
-- captive_ip4/6  : adresses IP du portail captif pour les RR A et AAAA.
-- raw_fd/_ifindex/_bridge_mac : socket AF_PACKET et infos bridge pour
--                 l'injection directe de la réponse DNS vers le client.
captive_domain = nil
captive_ip4    = nil
captive_ip6    = nil
raw_fd         = nil
_ifindex       = nil
_bridge_mac    = nil

--- Extrait le hostname d'une URL https?://host[:port]/...
-- Retourne nil si l'URL contient une IP brute (IPv4 x.x.x.x ou IPv6 [::]).
-- @tparam string|nil url URL du portail captif
-- @treturn string|nil Hostname en casse basse, ou nil
domain_from_url = (url) ->
  return nil unless url
  host = url\match "^https?://([^/:]+)"
  return nil unless host
  return nil if host\match "^%d+%.%d+%.%d+%.%d+$"   -- IPv4 brute
  return nil if host\match "^%["                      -- [IPv6] entre crochets
  host\lower!

-- ── Apprentissage MAC ────────────────────────────────────────────

--- Écrit une association IP→MAC vers le mac_learner.
-- Message binaire fixe : ip16 + mac6 = 22 octets.
-- IPv4 : 4 octets significatifs suivis de 12 zéros.
-- @tparam string ip_raw Adresse IP brute, 4 octets IPv4 ou 16 octets IPv6
-- @tparam string mac_raw Adresse MAC brute, 6 octets
-- @treturn boolean true si l'écriture complète a réussi
write_learn_msg = (ip_raw, mac_raw) ->
  return false unless mac_learn_wfd and mac_learn_wfd >= 0
  return false unless ip_raw and (#ip_raw == 4 or #ip_raw == 16)
  return false unless mac_raw and #mac_raw == 6

  msg = ffi.new "uint8_t[22]"

  if #ip_raw == 4
    for i = 1, 4
      msg[i - 1] = ip_raw\byte i
  else
    for i = 1, 16
      msg[i - 1] = ip_raw\byte i

  for i = 1, 6
    msg[15 + i] = mac_raw\byte i

  n = libc.write mac_learn_wfd, msg, 22
  n == 22

-- Helper : retourne la valeur sous forme de string, ou "-" si nil/vide.
-- @tparam any v  Valeur à formater
-- @treturn string Valeur formatée pour TSV
tsv_field = (v) ->
  s = if v ~= nil then tostring v else ""
  if #s == 0 then "-" else s

-- Extrait le nom de liste depuis un message de condition to_domainlist.
-- Exemple attendu: "Domain matched in list 'toulouse/malware'".
list_from_condition_reason = (condition_reason) ->
  return nil unless type(condition_reason) == "string"
  condition_reason\match "^Domain matched in list '([^']+)'$"

--- Envoie un événement de décision DNS vers worker_events (best-effort).
-- Écrit une ligne TSV sur le pipe events_wfd si disponible.
-- Format : ts<TAB>decision<TAB>qname<TAB>mac_src<TAB>src_ip<TAB>dst_ip<TAB>vlan
--          <TAB>user<TAB>af<TAB>reason<TAB>rule<LF>
-- Pas de qtype. Écriture atomique unique (≤ PIPE_BUF), EAGAIN ignoré silencieusement.
-- @tparam table  fields  Champs de la décision (qname, mac_src, src_ip, dst_ip, etc.)
-- @tparam        allowed Résultat de filter.decide : true, "dnsonly", ou false/nil
-- @treturn nil
write_event = (fields, allowed) ->
  return unless events_wfd
  decision = if allowed then "allow" else "block"
  line = table.concat({
    tostring os.time!
    decision
    tsv_field fields.qname
    tsv_field fields.mac_src
    tsv_field fields.src_ip
    tsv_field fields.dst_ip
    tsv_field fields.vlan
    tsv_field fields.user
    tsv_field fields.af
    tsv_field fields.reason
    tsv_field fields.rule
  }, "\t") .. "\n"
  libc.write events_wfd, line, #line

-- ── Parsing L3/L4/L7 ────────────────────────────────────────────

PROTO_UDP = 17
PROTO_TCP = 6

-- IPv6 extension header type → skip formula
IPV6_EXT_HDRS = {
  [0]:   true   -- Hop-by-Hop Options
  [43]:  true   -- Routing
  [44]:  true   -- Fragment
  [51]:  false  -- Authentication Header (AH)
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
      (p[off + 1] + 2) * 4   -- AH
    else
      (p[off + 1] + 1) * 8   -- standard
    return nil, nil if ext_size < 8 or off + ext_size > len
    off += ext_size
    nh   = next_nh
  nh, off

dns_tcp_complete = (buf) ->
  return false if #buf < 2
  #buf >= 2 + buf\byte(1) * 256 + buf\byte(2)

tcp_state = new_stream dns_tcp_complete

-- Extrait ip, l4, dns_msg depuis un paquet IP brut.
-- Retourne nil, "status" sur les cas spéciaux (buffering, tcp_control, parse_failed).
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

  if ip.version == 6
    p = ffi.cast "const uint8_t*", raw
    proto, l4_off_0based = skip_ipv6_ext_hdrs p, #raw, ip.next_header
    return nil, "parse_failed" unless proto
    l4_off = l4_off_0based + 1

  if proto == PROTO_UDP
    udp, _ = parse_udp raw, l4_off
    return nil, "parse_failed" unless udp
    dns_raw = raw\sub udp.data_off, udp.off + udp.len - 1
    dns_msg, _ = parse_dns dns_raw, 1, false
    return nil, "parse_failed" unless dns_msg
    udp.proto = "udp"
    return ip, udp, dns_msg

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
    return ip, tcp, dns_msg

  nil, "parse_failed"

-- ── Callback principal ───────────────────────────────────────────
handle_question = (qh_ptr, nfad, pkt_id) ->
  -- ── Payload brut ─────────────────────────────────────────────
  payload_ptr = ffi.new "unsigned char*[1]"
  payload_len = libnfq.nfq_get_payload nfad, payload_ptr
  return NF_DROP if payload_len <= 0

  raw = ffi.string payload_ptr[0], payload_len

  -- ── L2 ────────────────────────────────────────────────────
  -- MAC source via nfq_get_packet_hw() ; MAC destination non exposée par libnfq.
  l2 = get_l2 nfad

  -- ── L3 / L4 / L7 ───────────────────────────────────────────────
  ip, l4, dns_msg = parse_packet raw
  unless ip
    -- TCP segments arriving before a complete DNS message are buffered; let them through.
    return NF_ACCEPT if l4 == "buffering"
    -- TCP control segments (SYN/ACK/FIN without DNS payload) must pass.
    return NF_ACCEPT if l4 == "tcp_control"
    log_warn -> { action: "parse_failed", mac_src: l2.mac_src, status: l4 }
    return NF_DROP

  src_ip = ip2s ip.src
  dst_ip = ip2s ip.dst

  -- Log L2 metadata une fois le parse réussi (src_ip disponible pour corrélation).
  -- WARN si mac inconnue (nfq_get_packet_hw n'a rien retourné) pour faciliter
  -- le diagnostic sans avoir à passer en DEBUG.
  if l2.mac_src == "unknown"
    log_warn -> {
      action:     "l2_mac_missing"
      src_ip:     src_ip
      in_ifindex: l2.in_ifindex
      vlan:       l2.vlan
    }
  else
    log_debug -> {
      action:     "l2_info"
      mac_src:    l2.mac_src
      src_ip:     src_ip
      in_ifindex: l2.in_ifindex
      vlan:       l2.vlan
    }

  -- On ne traite que les questions (QR bit = 0)
  return NF_ACCEPT if dns_msg.header.qr

  -- Alimente le mac_learner avec les associations observées sur le trafic DNS.
  -- Écriture best-effort : l'échec ne doit pas bloquer ni refuser la requête DNS.
  write_learn_msg ip.src, l2.mac_raw

  -- ── Vol de question DNS pour le portail captif ───────────────────
  -- Si la question porte sur le hostname du portail captif (extrait de
  -- redirect_url), on forge la/les réponse(s) DNS (A ou AAAA) et on les injecte
  -- directement via AF_PACKET sur le bridge, comme le fait captive pour les TCP.
  -- La question originale est droptée (NF_DROP) ; aucun message IPC vers response.
  -- Cette approche est nécessaire car nfq_set_verdict(NF_ACCEPT, payload) ne
  -- peut pas inverser la direction d'un paquet (le paquet resterait sur le
  -- chemin LAN→WAN au lieu d'être renvoyé vers le client). UDP et TCP gérés :
  -- en TCP, forge_dns renvoie 2 segments (données PSH+ACK puis FIN+ACK).
  if captive_domain and raw_fd and _bridge_mac
    for _, q in ipairs dns_msg.questions
      norm = q.name\lower!\gsub "%.+$", ""
      if norm == captive_domain and (q.qtype == 1 or q.qtype == 28)   -- A ou AAAA
        mac_raw = l2.mac_raw
        if not mac_raw or mac_raw == "\0\0\0\0\0\0"
          log_warn -> {
            action:  "dns_steal_no_mac"
            domain:  q.name
            src_ip:  src_ip
          }
          break   -- MAC inconnue : laisser passer normalement
        forged_pkts = forge_dns.forge_dns_response ip, l4, dns_msg.header.id, q, captive_ip4, captive_ip6
        if forged_pkts
          ethertype = ip.version == 6 and IP6 or IP4
          sent_ok = true
          for pkt in *forged_pkts
            eth_bytes = "#{new_eth {src: _bridge_mac, dst: mac_raw, protocol: ethertype, vlan: l2.vlan, data: pkt}}"
            sent_ok = bridge_raw.send(raw_fd, eth_bytes, _ifindex) and sent_ok
          log_info -> {
            action:   "dns_stolen"
            domain:   q.name
            qtype:    dns_types[q.qtype] or "TYPE#{q.qtype}"
            proto:    l4.proto
            frames:   #forged_pkts
            src_ip:   src_ip
            resolver: dst_ip
            mac:      l2.mac_src
            ancount:  (captive_ip4 and q.qtype == 1 or captive_ip6 and q.qtype == 28) and 1 or 0
            sent:     sent_ok
          }
          return NF_DROP
        else
          log_warn -> {
            action:  "dns_steal_forge_failed"
            domain:  q.name
            qtype:   dns_types[q.qtype] or "TYPE#{q.qtype}"
            src_ip:  src_ip
          }
          break   -- forge échouée : laisser passer normalement

  -- ── Décision par question ────────────────────────────────────
  -- Un paquet DNS peut contenir plusieurs questions (rare en pratique,
  -- mais prévu par le RFC). On bloque si AU MOINS UNE question est refusée.
  -- Si toutes sont autorisées mais au moins une est "dnsonly", on envoie dnsonly.
  -- Décision par question : le comportement DNS spécifique (strip, dnsonly…)
  -- est entièrement porté par les callbacks on_response des actions, appelés
  -- par worker_responses via filter.get_rule_on_response(rule_id).
  -- Ici on ne fait que décider allow/refuse et écrire le message IPC correspondant.
  verdict         = NF_ACCEPT
  block_reason    = nil
  allow_reason    = nil
  block_rule_id   = nil
  allow_rule_id   = nil
  block_timeout   = nil
  allow_timeout   = nil
  block_modifiers = nil
  response_rule_ids = {}
  q_fields = {
    worker:   "dns"
    mac_src:  l2.mac_src
    vlan:     l2.vlan
    in_if:    tostring l2.in_ifindex
    src_ip:   src_ip
    dst_ip:   dst_ip
    src_port: l4.spt
    dst_port: l4.dpt
    txid:     string.format "0x%04x", dns_msg.header.id
    af:       ip.version == 6 and "ipv6" or "ipv4"
    user:     user_for_mac l2.mac_src, src_ip, auth_cfg.sessions_file
  }

  for _, q in ipairs dns_msg.questions
    q_fields.qname = q.name
    q_fields.qtype = dns_types[q.qtype] or "TYPE#{q.qtype}"
    req = {
      domain: q.name
      src_ip: src_ip
      mac:    l2.mac_src
      vlan:   l2.vlan
      ts:     os.time!
      user:   q_fields.user
    }
    allowed, reason, rule_id, nft_timeout, matched_list = nil, nil, nil, nil, nil
    decision = filter.decide_meta req
    if decision
      allowed     = decision.verdict
      reason      = decision.reason
      rule_id     = decision.rule_id
      nft_timeout = decision.timeout
      matched_list = list_from_condition_reason decision.condition_reason
      response_rule_ids = decision.response_rule_ids or {}
    q_fields.reason = reason or (allowed and "allowed") or "denied"
    q_fields.rule   = rule_id or ""
    q_fields.list   = matched_list
    if allowed
      log_allow -> q_fields
      metrics.record_verdict rule_id, "allow" if rule_id
      allow_reason  = reason
      allow_rule_id = rule_id
      allow_timeout = nft_timeout
    else
      log_block -> q_fields
      metrics.record_verdict rule_id, "refuse" if rule_id
      verdict         = NF_DROP
      block_reason    = reason
      block_rule_id   = rule_id
      block_timeout   = nft_timeout
      block_modifiers = decision and decision.modifiers or nil
    write_event q_fields, allowed

  -- Écriture IPC : write_msg pour les allow, write_refused_msg pour les refuse.
  -- Le comportement fin (strip DNS, injection nft…) est déterminé côté response
  -- par les callbacks on_response des actions, sans aucun code spécifique ici.
  benchmark_ms  = get_benchmark_ms!
  allow_timeout = allow_timeout or nft_cfg.ip_timeout
  block_timeout = block_timeout or nft_cfg.ip_timeout
  q_fields.timeout = if verdict == NF_ACCEPT then allow_timeout else block_timeout
  ipc_ok = false
  if verdict == NF_ACCEPT
    ipc_ok = write_msg pipe_wfd, dns_msg.header.id, ip.src, l4.spt, l2.mac_raw, ip.dst, allow_reason, benchmark_ms, allow_rule_id, allow_timeout, nil, response_rule_ids
  else
    ipc_ok = write_refused_msg pipe_wfd, dns_msg.header.id, ip.src, l4.spt, l2.mac_raw, ip.dst, block_reason, benchmark_ms, block_rule_id, block_timeout, block_modifiers, response_rule_ids

  unless ipc_ok
    log_warn -> {
      action: "ipc_write_failed"
      txid: string.format "0x%04x", dns_msg.header.id
      src_ip: src_ip
      dst_ip: dst_ip
      src_port: l4.spt
      user: q_fields.user
    }
    return NF_DROP

  NF_ACCEPT


-- ── Point d'entrée ───────────────────────────────────────────────
-- Appelé par main.moon après fork(), avec les fd des pipes IPC et filter_data.
run = (queue_num, wfd, learn_wfd, ev_wfd, filter_data) ->
  set_action_prefix "questions_"
  metrics.init config.metrics
  pipe_wfd      = wfd
  mac_learn_wfd = learn_wfd
  events_wfd    = ev_wfd

  -- Initialize filter with data passed from main.moon
  if filter_data
    filter.rules = filter_data.rules
    filter.auth_cfg_cache = filter_data.auth_cfg_cache
    filter.decision_cfg = filter_data.decision_cfg

  -- ── Interception DNS portail captif ─────────────────────────
  -- Lit redirect_url depuis auth_cfg pour extraire le hostname captif.
  -- Ouvre un socket AF_PACKET si un hostname est trouvé (comme captive).
  do
    auth = filter.get_auth_cfg!
    captive_domain = domain_from_url auth.redirect_url
    captive_ip4, captive_ip6 = detect_captive_ips auth
    if captive_domain
      ifname = auth.bridge_ifname or os.getenv("BRIDGE_IFNAME") or "br"
      fd, err = bridge_raw.open_socket ifname
      if fd
        raw_fd   = fd
        _ifindex = tonumber ffi.C.if_nametoindex ifname
        _bridge_mac = bridge_raw.read_mac ifname
        log_info -> {
          action:      "dns_steal_armed"
          domain:      captive_domain
          captive_ip4: captive_ip4 or "none"
          captive_ip6: captive_ip6 or "none"
          ifname:      ifname
        }
      else
        log_warn -> { action: "dns_steal_socket_failed", err: err, ifname: ifname, errno: tonumber(ffi.C.__errno_location()[0]) or 0 }
    else
      log_info -> { action: "dns_steal_disabled", reason: "no hostname in redirect_url" }

  run_queue tonumber(queue_num), handle_question

{ :run }
