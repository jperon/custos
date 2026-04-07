-- src/worker_q0.moon
-- Worker Q0 : traitement des questions DNS (UDP/53 src=LAN, dst=resolver).
--
-- Pour chaque paquet :
--   1. Parse L2 (MAC src via nfq_get_packet_hw)
--   2. Parse L3/L4/L7 via parse/ndpi (IPv4 et IPv6)
--   3. Vérifie allowlist → ACCEPT ou DROP
--   4. Si ACCEPT : envoie (txid, src_ip, src_port) dans le pipe IPC vers Q1
--   5. Si DROP : forge et envoie une réponse REFUSED (EDE=15) au client
--   6. Log structuré avec champs nDPI (ndpi_master / ndpi_app)

{ :ffi, :libnfq } = require "ffi_defs"
{ :QUEUE_QUESTIONS }     = require "config"
{ :get_l2 }              = require "parse/ethernet"
ndpi                     = require "parse/ndpi"
{ :is_allowed, :check_reload } = require "allowlist"
{ :write_msg }           = require "ipc"
{ :run_queue, :NF_ACCEPT, :NF_DROP } = require "nfq_loop"
{ :log_allow, :log_block, :log_warn } = require "log"
{ :build_refused }       = require "parse/dns"
refuse                   = require "refuse"

-- fd d'écriture du pipe IPC, injecté par main.moon avant fork()
pipe_wfd = nil

-- ── Callback principal ───────────────────────────────────────────
handle_question = (qh_ptr, nfad, pkt_id) ->
  -- Rechargement allowlist si SIGHUP reçu
  check_reload!

  -- ── L2 ───────────────────────────────────────────────────────
  l2 = get_l2 nfad

  -- ── Payload brut ─────────────────────────────────────────────
  payload_ptr = ffi.new "unsigned char*[1]"
  payload_len = libnfq.nfq_get_payload nfad, payload_ptr
  return NF_DROP if payload_len <= 0

  raw = ffi.string payload_ptr[0], payload_len

  -- ── L3 / L4 / L7 ─────────────────────────────────────────────
  pkt, parse_status = ndpi.parse_packet raw
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
  verdict  = NF_ACCEPT
  q_fields = {
    mac_src:     l2.mac_src
    in_if:       tostring l2.in_ifindex
    src_ip:      pkt.ip.src_ip
    dst_ip:      pkt.ip.dst_ip
    src_port:    pkt.l4.src_port
    dst_port:    pkt.l4.dst_port
    txid:        string.format "0x%04x", pkt.dns.txid
    af:          pkt.ip.version == 6 and "ipv6" or "ipv4"
    ndpi_master: pkt.ndpi_master
    ndpi_app:    pkt.ndpi_app
  }

  for _, q in ipairs pkt.questions
    q_fields.qname = q.qname
    q_fields.qtype = q.qtype_name
    if is_allowed q.qname
      q_fields.reason = nil
      log_allow q_fields
    else
      q_fields.reason = "not_in_allowlist"
      log_block q_fields
      verdict = NF_DROP

  -- Enregistre la transaction IPC pour Q1 : seulement si toutes les questions
  -- ont été autorisées (garantit qu'aucune fausse entrée n'entre dans pending).
  -- Inclut la MAC source pour que Q1 puisse résoudre les adresses cross-family.
  if verdict == NF_ACCEPT
    write_msg pipe_wfd, pkt.dns.txid, pkt.ip.src_ip_raw, pkt.l4.src_port, l2.mac_raw

  -- Réponse REFUSED au client (un seul envoi par paquet DNS)
  -- La question originale est copiée dans le payload REFUSED avec
  -- l'extension EDE code 15 (Filtered, RFC 8914).
  if verdict == NF_DROP
    -- For TCP, we simply DROP the packet to kill the connection/request
    -- as forging a TCP REFUSED response requires a full TCP stack.
    if pkt.l4.proto == "udp"
      dns_raw = raw\sub pkt.l4.off + 1, pkt.l4.off + pkt.l4.payload_len
      refused_payload = build_refused { hdr: pkt.dns }, dns_raw
      if refused_payload
        refuse.send_refused pkt.ip.src_ip_raw, pkt.l4.src_port,
                            refused_payload, pkt.ip.af

  verdict


-- ── Point d'entrée ───────────────────────────────────────────────
-- Appelé par main.moon après fork(), avec le fd d'écriture du pipe.
run = (wfd) ->
  pipe_wfd = wfd
  refuse.init!
  ndpi.warmup!
  run_queue QUEUE_QUESTIONS, handle_question
  ndpi.cleanup!

{ :run }
