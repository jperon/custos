-- src/nfq_loop.moon
-- Boucle NFQUEUE générique : ouvre une queue, installe le callback,
-- tourne jusqu'à erreur. Factorisé pour être réutilisé par Q0 et Q1.
-- Le caller fournit le numéro de queue et la fonction de callback Lua.

{ :ffi, :libc, :libnfq } = require "ffi_defs"
{ :AF_INET, :AF_INET6 } = require "config"
{ :log_info, :log_warn, :log_error, :log_debug } = require "log"

AF_BRIDGE = 7   -- Linux AF_BRIDGE : famille d'adresses pour les hooks bridge nftables

-- Constantes NFQUEUE
NFQNL_COPY_PACKET = 2   -- copie complète du paquet (payload inclus)
NF_DROP    = 0
NF_ACCEPT  = 1
NF_REPEAT  = 3           -- rejoue la règle (non utilisé ici)

EINTR = 4                -- code errno Linux : appel interrompu par signal

-- Taille du buffer de lecture netlink (doit être > MTU + overhead netlink)
READ_BUF_SIZE = 65536

-- Sentinel : le callback a déjà posé son propre verdict (ex: Q1 avec payload patché)
VERDICT_DONE = -1

--- Lance la boucle de traitement d'une queue NFQUEUE.
-- Ouvre la queue, installe le callback C, et tourne jusqu'à erreur ou SIGINT.
-- Bloque jusqu'à la fermeture du fd netlink.
-- @tparam number   queue_num Numéro de queue NFQUEUE (uint16)
-- @tparam function callback  function(qh_ptr, nfad, pkt_id) → NF_ACCEPT | NF_DROP | VERDICT_DONE
-- @treturn nil
run_queue = (queue_num, callback) ->
  log_info { action: "queue_open", queue: queue_num }

  log_debug { action: "queue_nfq_open_call", queue: queue_num }
  h = libnfq.nfq_open!
  if h == nil
    errno = tonumber(ffi.C.__errno_location()[0])
    log_error { action: "queue_nfq_open_failed", queue: queue_num, errno: errno }
    error "nfq_open() échoué"

  log_debug { action: "queue_bind_pf", queue: queue_num }
  -- bind_pf : attache le handle aux familles AF_INET et AF_INET6 (et AF_BRIDGE en mode bridge).
  -- Peut renvoyer une erreur si déjà bindé par un autre handle dans le process ;
  -- on ignore l'erreur (comportement historique de libnetfilter_queue).
  libnfq.nfq_bind_pf h, AF_INET
  libnfq.nfq_bind_pf h, AF_INET6
  libnfq.nfq_bind_pf h, AF_BRIDGE

  -- Pointeur partagé entre la closure C et la closure Lua du callback
  qh_box = ffi.new "nfq_q_handle*[1]"

  log_debug { action: "queue_callback_setup", queue: queue_num }
  -- Wrapper C minimal : extrait pkt_id et délègue au callback Lua
  c_callback = ffi.cast "nfq_callback", (qh, nfmsg, nfad, data) ->
    -- Extraction de l'id du paquet depuis le header nfq
    -- nfq_get_msg_packet_hdr retourne un pointeur vers nfqnl_msg_packet_hdr
    -- dont le premier champ packet_id est en big-endian.
    raw_hdr = libnfq.nfq_get_msg_packet_hdr nfad
    pkt_id  = libc.ntohl raw_hdr.packet_id

    ok, verdict = pcall callback, qh_box[0], nfad, pkt_id
    unless ok
      -- En cas d'exception Lua dans le callback, on bloque le paquet
      -- (fail-closed) pour éviter tout contournement du filtrage DNS.
      log_error { action: "callback_exception", err: tostring(verdict), queue: queue_num }
      verdict = NF_DROP

    -- Si verdict == VERDICT_DONE, le callback a déjà appelé nfq_set_verdict
    -- (ex: Q1 qui envoie un payload modifié) → on ne repose pas de verdict.
    if verdict != VERDICT_DONE
      libnfq.nfq_set_verdict qh_box[0], pkt_id, verdict, 0, nil
    0   -- retour C : 0 = succès


  log_debug { action: "queue_create_queue_call", queue: queue_num }
  qh = libnfq.nfq_create_queue h, queue_num, c_callback, nil
  if qh == nil
    errno = tonumber(ffi.C.__errno_location()[0])
    log_error { action: "queue_create_queue_failed", queue: queue_num, errno: errno }
    error "nfq_create_queue(#{queue_num}) échoué"

  qh_box[0] = qh

  -- Copie complète du paquet (payload + métadonnées L2)
  log_debug { action: "queue_set_mode_call", queue: queue_num }
  libnfq.nfq_set_mode qh, NFQNL_COPY_PACKET, READ_BUF_SIZE

  fd  = libnfq.nfq_fd h
  buf = ffi.new "char[65536]"

  log_info { action: "queue_listening", queue: queue_num, pid: tonumber(ffi.C.getpid and ffi.C.getpid() or 0) }

  while true
    log_debug { action: "queue_read_call", queue: queue_num }
    rv = libc.read fd, buf, READ_BUF_SIZE
    if rv > 0
      log_debug { action: "queue_handle_packet", queue: queue_num, rv: rv }
      libnfq.nfq_handle_packet h, buf, tonumber rv
    elseif rv == 0
      log_warn { action: "queue_read_eof", queue: queue_num }
      break   -- EOF inattendu
    else
      -- rv < 0 : EINTR (signal reçu) → on sort proprement
      en = libc.__errno_location()[0]
      if en == EINTR
        log_debug { action: "queue_read_eintr", queue: queue_num }
        break
      log_warn { action: "queue_read_error", queue: queue_num, errno: en }
      break   -- autre erreur (ENOBUFS, etc.) → on sort

  log_info { action: "queue_closed", queue: queue_num }
  libnfq.nfq_destroy_queue qh
  libnfq.nfq_close h
  c_callback\free!   -- libère le wrapper ffi.cast

-- Verdict helpers exposés pour les workers
{ :run_queue, :NF_ACCEPT, :NF_DROP, :VERDICT_DONE }
