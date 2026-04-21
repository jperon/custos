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

{ :ffi, :libnfq } = require "ffi_defs"
{ :QUEUE_QUESTIONS, :AUTH_SESSIONS_FILE } = require "config"
{ :get_l2, :ETH_OFFSET } = require "parse/ethernet"
ndpi                     = require "parse/ndpi"
filter                   = require "filter"
{ :write_msg, :write_refused_msg, :write_dnsonly_msg } = require "ipc"
{ :run_queue, :NF_ACCEPT, :NF_DROP } = require "nfq_loop"
{ :log_allow, :log_block, :log_warn } = require "log"
{ :user_for_ip } = require "auth.sessions"

-- fd d'écriture du pipe IPC, injecté par main.moon avant fork()
pipe_wfd = nil

-- ── Callback principal ───────────────────────────────────────────
handle_question = (qh_ptr, nfad, pkt_id) ->
  -- Rechargement filtre si SIGHUP reçu
  filter.reload!

  -- ── Payload brut ─────────────────────────────────────────────
  payload_ptr = ffi.new "unsigned char*[1]"
  payload_len = libnfq.nfq_get_payload nfad, payload_ptr
  return NF_DROP if payload_len <= 0

  raw = ffi.string payload_ptr[0], payload_len

  -- ── L2 ───────────────────────────────────────────────────────
  -- En mode bridge, raw est passé à get_l2 pour extraire la MAC depuis la trame.
  l2 = get_l2 nfad, raw

  -- ── L3 / L4 / L7 ─────────────────────────────────────────────
  pkt, parse_status = ndpi.parse_packet raw, ETH_OFFSET
  unless pkt
    -- TCP segments arriving before a complete DNS message are buffered; let them through.
    return NF_ACCEPT if parse_status == "buffering"
    -- TCP control segments (SYN/ACK/FIN without DNS payload) must pass.
    return NF_ACCEPT if parse_status == "tcp_control"
    log_warn { action: "parse_failed", mac_src: l2.mac_src }
    return NF_DROP

  -- ── nDPI State Tracking ──────────────────────────────────────
  ndpi.get_flow pkt
  if math.random(1000) == 1
    ndpi.purge_flows!

  -- On ne traite que les questions (QR bit = 0)
  return NF_ACCEPT if pkt.dns.is_response

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
    user:        user_for_ip pkt.ip.src_ip, AUTH_SESSIONS_FILE, l2.mac_src
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
    allowed, reason = filter.decide req
    if allowed == "dnsonly"
      q_fields.reason = "dnsonly"
      log_allow q_fields
      dnsonly = true
    elseif allowed
      q_fields.reason = nil
      log_allow q_fields
    else
      q_fields.reason = reason or "denied"
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
-- Appelé par main.moon après fork(), avec le fd d'écriture du pipe.
run = (wfd) ->
  pipe_wfd = wfd
  filter.load!
  ndpi.warmup!
  -- Apply extra nft rules from UCI once at startup (inserted at head of `forward` chain)
  nft_extra = require "nft_extra_rules"
  nft_extra.apply_from_config()
  run_queue QUEUE_QUESTIONS, handle_question
  -- Cleanup extra nft rules inserted at startup
  nft_extra.cleanup()
  ndpi.cleanup!

{ :run }
