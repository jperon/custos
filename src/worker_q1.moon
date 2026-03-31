-- src/worker_q1.moon
-- Worker Q1 : traitement des réponses DNS (UDP/53 dst=LAN, src=resolver).
--
-- Pour chaque paquet :
--   1. Draine le pipe IPC (absorbe les tokens Q0 → table pending)
--   2. Parse L3/L4/L7
--   3. Vérifie que la transaction (txid, dst_ip, dst_port) est dans pending
--      (dst_ip/dst_port de la réponse = src_ip/src_port de la question)
--   4. Si autorisée :
--        a. Patch TTL de tous les RR → 60 secondes
--        b. Recalcule checksum UDP et IP
--        c. Ajoute les IPs A/AAAA dans les sets nft (timeout 2m)
--        d. Envoie le paquet modifié avec NF_ACCEPT + payload
--   5. Si non autorisée (réponse forgée ou question bloquée) : NF_DROP

{ :ffi, :libc, :libnfq } = require "ffi_defs"
{ :QUEUE_RESPONSES }     = require "config"
{ :parse_ip }            = require "parse/ip"
{ :parse_udp, :checksum_udp } = require "parse/udp"
{ :parse_dns, :patch_ttl, :QTYPE } = require "parse/dns"
{ :drain_pipe, :is_pending, :consume } = require "ipc"
{ :add_ip }              = require "nft"
{ :run_queue, :NF_ACCEPT, :NF_DROP } = require "nfq_loop"
{ :log_allow, :log_block, :log_info, :log_warn, :now } = require "log"

bit = require "bit"

-- TTL forcé sur toutes les réponses passantes (secondes)
FORCED_TTL = 60

-- fd de lecture du pipe IPC, injecté par main.moon avant fork()
pipe_rfd = nil

-- ── Patch in-place du paquet ─────────────────────────────────────
-- Modifie le buffer ffi mutable : TTL DNS + checksums UDP/IP.
-- Retourne la string Lua du paquet modifié (pour nfq_set_verdict).
patch_packet = (raw, ip_hdr, udp_hdr, dns) ->
  -- Copie mutable du paquet dans un buffer ffi
  pkt_len = #raw
  buf     = ffi.new "uint8_t[?]", pkt_len
  ffi.copy buf, raw, pkt_len

  -- ── 1. Patch TTL dans les RR DNS ─────────────────────────────
  -- dns_offset : offset 0-based du début DNS dans le paquet IP brut
  -- = ihl (octets) + 8 (UDP header) — les deux en 0-based
  dns_offset_0 = ip_hdr.ihl + 8   -- 0-based
  patch_ttl buf, dns.answers, dns_offset_0, FORCED_TTL

  -- ── 2. Recalcul checksum UDP ─────────────────────────────────
  -- On reconstruit une string Lua depuis le buffer modifié pour
  -- les fonctions de checksum (qui travaillent sur strings).
  patched_raw = ffi.string buf, pkt_len
  new_udp_cksum = checksum_udp patched_raw, ip_hdr, udp_hdr

  -- Écriture du nouveau checksum UDP (big-endian, offset udp_off+6, 1-based)
  cksum_off   = udp_hdr.udp_off + 6 - 1   -- 0-based
  buf[cksum_off]   = bit.rshift bit.band(new_udp_cksum, 0xFF00), 8
  buf[cksum_off+1] = bit.band new_udp_cksum, 0xFF

  -- ── 3. Recalcul checksum IP ──────────────────────────────────
  -- On met le champ checksum IP à zéro avant recalcul
  buf[10] = 0; buf[11] = 0   -- 0-based : octets 10-11 (checksum IP)
  ip_header_str = ffi.string buf, ip_hdr.ihl
  { :checksum_ip } = require "parse/ip"
  new_ip_cksum  = checksum_ip ip_header_str
  buf[10] = bit.rshift bit.band(new_ip_cksum, 0xFF00), 8
  buf[11] = bit.band new_ip_cksum, 0xFF

  -- Retourne la string finale (copiée depuis ffi buf)
  ffi.string buf, pkt_len

-- ── Callback principal ───────────────────────────────────────────
handle_response = (qh_ptr, nfad, pkt_id) ->
  -- ── Drain pipe IPC ───────────────────────────────────────────
  -- Absorbe tous les tokens disponibles de Q0 avant de traiter ce paquet.
  drain_pipe pipe_rfd, now

  -- ── Payload brut ─────────────────────────────────────────────
  payload_ptr = ffi.new "unsigned char*[1]"
  payload_len = libnfq.nfq_get_payload nfad, payload_ptr
  return NF_DROP if payload_len <= 0

  raw = ffi.string payload_ptr[0], payload_len

  -- ── L3 / L4 ──────────────────────────────────────────────────
  ip_hdr  = parse_ip raw
  return NF_ACCEPT unless ip_hdr   -- fail-open sur non-IP

  udp_hdr = parse_udp raw, ip_hdr
  return NF_ACCEPT unless udp_hdr

  -- ── L7 ───────────────────────────────────────────────────────
  dns = parse_dns udp_hdr.dns_payload
  return NF_ACCEPT unless dns
  return NF_ACCEPT unless dns.hdr.is_response   -- ne traiter que les réponses

  -- La question originale avait src_ip=ip_hdr.dst_ip, src_port=udp_hdr.dst_port
  -- (la réponse est adressée au client LAN)
  client_ip   = ip_hdr.dst_ip_raw
  client_port = udp_hdr.dst_port
  txid        = dns.hdr.txid

  -- ── Vérification IPC ─────────────────────────────────────────
  unless is_pending txid, ip_hdr.dst_ip, client_port, now
    log_block {
      action:    "response_no_matching_question"
      src_ip:    ip_hdr.src_ip
      dst_ip:    ip_hdr.dst_ip
      txid:      string.format "0x%04x", txid
      rcode:     dns.hdr.rcode
    }
    return NF_DROP

  -- Transaction consommée (one-shot : une réponse par question)
  consume txid, ip_hdr.dst_ip, client_port

  -- ── Extraction des IPs des RR et injection nft ───────────────
  ip_count = 0
  for ans in *dns.answers
    if ans.rtype == QTYPE.A or ans.rtype == QTYPE.AAAA
      add_ip ans.rdata_str
      ip_count += 1

  -- ── Patch TTL + checksums ─────────────────────────────────────
  patched = patch_packet raw, ip_hdr, udp_hdr, dns

  -- Log de la réponse
  qnames = table.concat [q.qname for q in *dns.questions], ","
  log_allow {
    action:   "response_patched"
    src_ip:   ip_hdr.src_ip
    dst_ip:   ip_hdr.dst_ip
    txid:     string.format "0x%04x", txid
    qnames:   qnames
    answers:  ip_count
    ttl_set:  FORCED_TTL
    rcode:    dns.hdr.rcode
  }

  -- ── Verdict avec payload modifié ─────────────────────────────
  -- nfq_set_verdict est appelé par nfq_loop.moon APRÈS le retour du callback
  -- avec le verdict simple NF_ACCEPT (sans payload).
  -- Pour envoyer le payload modifié, on appelle nfq_set_verdict directement ici
  -- puis on retourne un sentinel indiquant que le verdict est déjà posé.
  -- → On utilise NF_ACCEPT : nfq_loop appellera set_verdict(NF_ACCEPT, 0, nil)
  --   ce qui est idempotent si le paquet a déjà été répondu... mais NON :
  --   un double verdict corrompt la queue.
  --
  -- Solution : on retourne le paquet modifié en utilisant nfq_set_verdict
  -- avec datalen > 0 directement ici, puis on retourne le sentinel -1
  -- pour que nfq_loop.moon sache qu'il ne doit PAS rappeler set_verdict.
  patched_ptr = ffi.cast "const unsigned char*", patched
  libnfq.nfq_set_verdict qh_ptr, pkt_id, NF_ACCEPT, #patched, patched_ptr

  -1   -- sentinel : verdict déjà posé, nfq_loop ne doit pas reposer de verdict

-- ── Point d'entrée ───────────────────────────────────────────────
run = (rfd) ->
  pipe_rfd = rfd
  run_queue QUEUE_RESPONSES, handle_response

{ :run }
