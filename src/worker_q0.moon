-- src/worker_q0.moon
-- Worker Q0 : traitement des questions DNS (UDP/53 src=LAN, dst=resolver).
--
-- Pour chaque paquet :
--   1. Parse L2 (MAC src via nfq_get_packet_hw)
--   2. Parse L3 (IPv4/IPv6)
--   3. Parse L4 (UDP)
--   4. Parse L7 (DNS question — qname, qtype)
--   5. Vérifie allowlist → ACCEPT ou REJECT
--   6. Si ACCEPT : envoie (txid, src_ip, src_port) dans le pipe IPC vers Q1
--   7. Log structuré

{ :ffi, :libc, :libnfq } = require "ffi_defs"
{ :QUEUE_QUESTIONS }     = require "config"
{ :get_l2 }              = require "parse/ethernet"
{ :parse_ip }            = require "parse/ip"
{ :parse_udp }           = require "parse/udp"
{ :parse_dns }           = require "parse/dns"
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

  -- ── L3 ───────────────────────────────────────────────────────
  ip_hdr = parse_ip raw
  unless ip_hdr
    log_warn { action: "parse_ip_failed", mac_src: l2.mac_src }
    return NF_ACCEPT   -- fail-open sur paquet non-IP

  -- ── L4 ───────────────────────────────────────────────────────
  udp_hdr = parse_udp raw, ip_hdr
  unless udp_hdr
    log_warn { action: "parse_udp_failed", src: ip_hdr.src_ip }
    return NF_ACCEPT

  -- ── L7 ───────────────────────────────────────────────────────
  dns = parse_dns udp_hdr.dns_payload
  unless dns
    log_warn { action: "parse_dns_failed", src: ip_hdr.src_ip }
    return NF_ACCEPT

  -- On ne traite que les questions (QR bit = 0)
  return NF_ACCEPT if dns.hdr.is_response

  -- ── Décision par question ────────────────────────────────────
  -- Un paquet DNS peut contenir plusieurs questions (rare en pratique,
  -- mais prévu par le RFC). On bloque si AU MOINS UNE question est refusée.
  verdict  = NF_ACCEPT
  q_fields = {
    mac_src:   l2.mac_src
    in_if:     tostring l2.in_ifindex
    src_ip:    ip_hdr.src_ip
    dst_ip:    ip_hdr.dst_ip
    src_port:  udp_hdr.src_port
    dst_port:  udp_hdr.dst_port
    txid:      string.format "0x%04x", dns.hdr.txid
    af:        ip_hdr.version == 6 and "ipv6" or "ipv4"
  }

  for _, q in ipairs dns.questions
    if is_allowed q.qname
      log_allow {
        unpack {k, v for k, v in pairs q_fields}   -- merge
        qname: q.qname
        qtype: q.qtype_name
      }
    else
      log_block {
        unpack {k, v for k, v in pairs q_fields}
        qname: q.qname
        qtype: q.qtype_name
        reason: "not_in_allowlist"
      }
      verdict = NF_DROP

  -- Enregistre la transaction IPC pour Q1 : seulement si toutes les questions
  -- ont été autorisées (garantit qu'aucune fausse entrée n'entre dans pending).
  if verdict == NF_ACCEPT
    write_msg pipe_wfd, dns.hdr.txid, ip_hdr.src_ip_raw, udp_hdr.src_port

  -- Réponse REFUSED au client (un seul envoi par paquet DNS)
  -- La question originale est copiée dans le payload REFUSED avec
  -- l'extension EDE code 15 (Filtered, RFC 8914).
  if verdict == NF_DROP
    refused_payload = build_refused dns, udp_hdr.dns_payload
    if refused_payload
      refuse.send_refused ip_hdr.src_ip_raw, udp_hdr.src_port,
                          refused_payload, ip_hdr.af

  verdict

-- ── Point d'entrée ───────────────────────────────────────────────
-- Appelé par main.moon après fork(), avec le fd d'écriture du pipe.
run = (wfd) ->
  pipe_wfd = wfd
  refuse.init!
  run_queue QUEUE_QUESTIONS, handle_question

{ :run }
