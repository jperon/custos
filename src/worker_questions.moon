-- src/worker_q0.moon
-- Worker Q0 : traitement des questions DNS (UDP/53 src=LAN, dst=resolver).
--
-- Pour chaque paquet :
--   1. Parse L2 (MAC src via nfq_get_packet_hw)
--   2. Parse L3/L4/L7 via parse/ndpi (IPv4 et IPv6)
--   3. Vérifie allowlist → décide allow ou refuse
--   4. Si autorisé : envoie write_msg (allowed) dans le pipe IPC vers Q1, NF_ACCEPT
--   5. Si refusé   : envoie write_refused_msg dans le pipe IPC vers Q1, NF_ACCEPT
--      Q1 intercepte la réponse du serveur et la transforme en REFUSED+EDE
--   6. Log structuré avec champs nDPI (ndpi_master / ndpi_app)

{ :ffi, :libc, :libnfq } = require "ffi_defs"
{ :QUEUE_QUESTIONS, :AUTH_SESSIONS_FILE } = require "config"
{ :get_l2 } = require "parse/ethernet"
ndpi                     = require "parse/ndpi"
filter                   = require "filter"
{ :write_msg, :write_refused_msg, :write_dnsonly_msg } = require "ipc"
{ :run_queue, :NF_ACCEPT, :NF_DROP } = require "nfq_loop"
{ :log_allow, :log_block, :log_warn, :log_debug } = require "log"
{ :user_for_mac } = require "auth.sessions"

-- fd d'écriture du pipe IPC Q0→Q1, injecté par main.moon avant fork()
pipe_wfd = nil

-- fd d'écriture du pipe d'apprentissage Q0→mac_learner.
mac_learn_wfd = nil

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
  pkt, parse_status = ndpi.parse_packet raw
  unless pkt
    -- TCP segments arriving before a complete DNS message are buffered; let them through.
    return NF_ACCEPT if parse_status == "buffering"
    -- TCP control segments (SYN/ACK/FIN without DNS payload) must pass.
    return NF_ACCEPT if parse_status == "tcp_control"
    log_warn { action: "parse_failed", mac_src: l2.mac_src }
    return NF_DROP

  -- Log L2 metadata une fois le parse réussi (src_ip disponible pour corrélation).
  -- WARN si mac inconnue (nfq_get_packet_hw n'a rien retourné) pour faciliter
  -- le diagnostic sans avoir à passer en DEBUG.
  if l2.mac_src == "unknown"
    log_warn {
      action:     "l2_mac_missing"
      src_ip:     pkt.ip.src_ip
      in_ifindex: l2.in_ifindex
      vlan:       l2.vlan
    }
  else
    log_debug {
      action:     "l2_info"
      mac_src:    l2.mac_src
      src_ip:     pkt.ip.src_ip
      in_ifindex: l2.in_ifindex
      vlan:       l2.vlan
    }

  -- ── nDPI State Tracking ──────────────────────────────────────
  ndpi.get_flow pkt
  if math.random(1000) == 1
    ndpi.purge_flows!
    ndpi.purge_tcp_buffers!

  -- On ne traite que les questions (QR bit = 0)
  return NF_ACCEPT if pkt.dns.is_response

  -- Alimente le mac_learner avec les associations observées sur le trafic DNS.
  -- Écriture best-effort : l'échec ne doit pas bloquer ni refuser la requête DNS.
  write_learn_msg pkt.ip.src_ip_raw, l2.mac_raw

  -- ── Décision par question ────────────────────────────────────
  -- Un paquet DNS peut contenir plusieurs questions (rare en pratique,
  -- mais prévu par le RFC). On bloque si AU MOINS UNE question est refusée.
  -- Si toutes sont autorisées mais au moins une est "dnsonly", on envoie dnsonly.
  verdict  = NF_ACCEPT
  dnsonly  = false
  q_fields = {
    mac_src:     l2.mac_src
    vlan:        l2.vlan
    in_if:       tostring l2.in_ifindex
    src_ip:      pkt.ip.src_ip
    dst_ip:      pkt.ip.dst_ip
    src_port:    pkt.l4.src_port
    dst_port:    pkt.l4.dst_port
    txid:        string.format "0x%04x", pkt.dns.txid
    af:          pkt.ip.version == 6 and "ipv6" or "ipv4"
    ndpi_master: pkt.ndpi_master
    ndpi_app:    pkt.ndpi_app
    user:        user_for_mac l2.mac_src, pkt.ip.src_ip, AUTH_SESSIONS_FILE
  }

  for _, q in ipairs pkt.questions
    q_fields.qname = q.qname
    q_fields.qtype = q.qtype_name
    req = {
      domain: q.qname
      src_ip: pkt.ip.src_ip
      mac:    l2.mac_src
      vlan:   l2.vlan
      ts:     os.time!
    }
    allowed, reason, rule = filter.decide req
    q_fields.reason = reason or (allowed == "dnsonly" and "dnsonly") or (allowed and "allowed") or "denied"
    q_fields.rule = rule or ""
    if allowed == "dnsonly"
      log_allow q_fields
      dnsonly = true
    elseif allowed
      log_allow q_fields
    else
      log_block q_fields
      verdict = NF_DROP

  -- Enregistre la transaction IPC pour Q1 (toujours NF_ACCEPT — Q1 gère tout).
  -- Si autorisé   : Q1 patche TTL + injecte EDE "Custos vigilat."
  -- Si dnsonly    : Q1 patche TTL + EDE mais n'injecte pas les IPs dans nft
  -- Si refusé     : Q1 transforme la réponse du serveur en REFUSED+EDE Filtered
  ipc_ok = false
  if verdict == NF_ACCEPT
    if dnsonly
      ipc_ok = write_dnsonly_msg pipe_wfd, pkt.dns.txid, pkt.ip.src_ip_raw, pkt.l4.src_port, l2.mac_raw, pkt.ip.dst_ip_raw
    else
      ipc_ok = write_msg pipe_wfd, pkt.dns.txid, pkt.ip.src_ip_raw, pkt.l4.src_port, l2.mac_raw, pkt.ip.dst_ip_raw
  else
    ipc_ok = write_refused_msg pipe_wfd, pkt.dns.txid, pkt.ip.src_ip_raw, pkt.l4.src_port, l2.mac_raw, pkt.ip.dst_ip_raw

  unless ipc_ok
    log_warn {
      action: "ipc_write_failed"
      txid: string.format "0x%04x", pkt.dns.txid
      src_ip: pkt.ip.src_ip
      dst_ip: pkt.ip.dst_ip
      src_port: pkt.l4.src_port
      user: q_fields.user
    }
    return NF_DROP

  NF_ACCEPT


-- ── Point d'entrée ───────────────────────────────────────────────
-- Appelé par main.moon après fork(), avec les fd des pipes IPC.
run = (queue_num, wfd, learn_wfd) ->
  pipe_wfd      = wfd
  mac_learn_wfd = learn_wfd
  ndpi.warmup!
  run_queue tonumber(queue_num), handle_question
  ndpi.cleanup!

{ :run }
