-- src/worker_q1.moon
-- Worker Q1 : traitement des réponses DNS (UDP/53 dst=LAN, src=resolver).
--
-- Pour chaque paquet :
--   1. Draine le pipe IPC (absorbe les tokens Q0 → table pending)
--   2. Parse L3/L4/L7 via parse/ndpi (IPv4 et IPv6)
--   3. Vérifie que la transaction (txid, dst_ip, dst_port) est dans pending
--      (dst_ip/dst_port de la réponse = src_ip/src_port de la question)
--   4. Si autorisée :
--        a. Parse les RR DNS de la réponse
--        b. Patch TTL de tous les RR → FORCED_TTL secondes
--        c. Recalcule checksums UDP (pseudo-header IPv4 ou IPv6) et IP (IPv4)
--        d. Ajoute les IPs A/AAAA dans les sets nft (timeout 2m)
--        e. Envoie le paquet modifié avec NF_ACCEPT + payload
--   5. Si non autorisée (réponse forgée ou question bloquée) : NF_DROP

{ :ffi, :libc, :libnfq } = require "ffi_defs"
{ :QUEUE_RESPONSES, :DOCKER_MODE, :FORCED_TTL } = require "config"
ndpi = require "parse/ndpi"
{ :QTYPE } = ndpi
{ :drain_pipe, :is_pending, :consume } = require "ipc"
{ :add_ip }              = require "nft"
{ :run_queue, :NF_ACCEPT, :NF_DROP } = require "nfq_loop"
{ :log_allow, :log_block, :log_info, :now } = require "log"

-- fd de lecture du pipe IPC, injecté par main.moon avant fork()
pipe_rfd = nil

-- ── Callback principal ───────────────────────────────────────────
--- Process a DNS response packet from NFQUEUE.
-- Drains IPC, validates the transaction, patches TTL+checksums,
-- injects resolved IPs into nftables, and sets the verdict.
-- @tparam cdata  qh_ptr  nfq_q_handle pointer (for nfq_set_verdict)
-- @tparam cdata  nfad    nfq_data pointer
-- @tparam number pkt_id  NFQUEUE packet id
-- @treturn number NF_ACCEPT, NF_DROP, or -1 (verdict already set)
handle_response = (qh_ptr, nfad, pkt_id) ->
  -- ── Drain pipe IPC ───────────────────────────────────────────
  -- Absorbe tous les tokens disponibles de Q0 avant de traiter ce paquet.
  drain_pipe pipe_rfd, now

  -- ── Payload brut ─────────────────────────────────────────────
  payload_ptr = ffi.new "unsigned char*[1]"
  payload_len = libnfq.nfq_get_payload nfad, payload_ptr
  if payload_len <= 0
    return NF_DROP

  raw = ffi.string payload_ptr[0], payload_len

  -- ── L3 / L4 / L7 ─────────────────────────────────────────────
  -- parse_packet gère IPv4 et IPv6, UDP et TCP, et le header DNS en un seul appel.
  pkt, parse_status = ndpi.parse_packet raw
  unless pkt
    -- TCP segments before a complete DNS message are buffered silently; let them through.
    return NF_ACCEPT

  -- Pass to nDPI for flow state tracking (TCP sequence, etc.)
  ndpi.get_flow pkt
  if math.random(1000) == 1
    ndpi.purge_flows!

  unless pkt.dns.is_response
    return NF_ACCEPT

  -- La question originale avait src_ip=pkt.ip.dst_ip, src_port=pkt.l4.dst_port
  -- (la réponse est adressée au client LAN).
  client_port = pkt.l4.dst_port
  txid        = pkt.dns.txid

  -- ── Vérification IPC ─────────────────────────────────────────
  -- En mode Docker, on saute la vérification IPC car les requêtes
  -- et réponses sont vues depuis la perspective du conteneur (OUTPUT).
  unless DOCKER_MODE
    unless is_pending txid, pkt.ip.dst_ip, client_port, now
      log_block {
        action:    "response_no_matching_question"
        src_ip:    pkt.ip.src_ip
        dst_ip:    pkt.ip.dst_ip
        txid:      string.format "0x%04x", txid
        rcode:     pkt.dns.rcode
      }
      return NF_DROP
    -- Transaction consommée (one-shot : une réponse par question)
    consume txid, pkt.ip.dst_ip, client_port

  -- ── Parse RR DNS + injection nft ─────────────────────────────
  answers  = ndpi.parse_answers raw, pkt
  ip_count = 0
  for ans in *answers
    if ans.rtype == QTYPE.A or ans.rtype == QTYPE.AAAA
      add_ip ans.rdata_str
      ip_count += 1

  -- ── Patch TTL + checksums (IPv4 et IPv6) ─────────────────────
  -- patch_and_checksum réécrit les TTL DNS, recalcule le checksum UDP
  -- (pseudo-header IPv4 ou IPv6 selon pkt.ip.version), et le checksum
  -- IP header pour IPv4 (IPv6 n'en a pas).
  patched = ndpi.patch_and_checksum raw, pkt, answers, FORCED_TTL

  -- Log de la réponse
  qnames = table.concat [q.qname for q in *pkt.questions], ","
  log_allow {
    action:      "response_patched"
    src_ip:      pkt.ip.src_ip
    dst_ip:      pkt.ip.dst_ip
    txid:        string.format "0x%04x", txid
    qnames:      qnames
    answers:     ip_count
    ttl_set:     FORCED_TTL
    rcode:       pkt.dns.rcode
    ndpi_master: pkt.ndpi_master
    ndpi_app:    pkt.ndpi_app
  }

  -- ── Verdict avec payload modifié ─────────────────────────────
  -- On appelle nfq_set_verdict directement ici avec le payload modifié,
  -- puis on retourne le sentinel -1 pour que nfq_loop ne repose
  -- un second verdict (ce qui corromprait la queue).
  patched_ptr = ffi.cast "const unsigned char*", patched
  libnfq.nfq_set_verdict qh_ptr, pkt_id, NF_ACCEPT, #patched, patched_ptr

  -1   -- sentinel : verdict déjà posé, nfq_loop ne doit pas reposer de verdict


-- ── Point d'entrée ───────────────────────────────────────────────
--- Start the Q1 response worker.
-- Blocks in the NFQUEUE loop until the process exits.
-- @tparam number rfd Read end of the IPC pipe from Q0.
run = (rfd) ->
  pipe_rfd = rfd
  -- Pré-initialise le module nDPI avant le démarrage de la boucle pour éviter
  -- une latence de 1–2 s sur le premier paquet (ndpi_init_detection_module).
  ndpi.warmup!
  run_queue QUEUE_RESPONSES, handle_response
  ndpi.cleanup!

{ :run }
