-- src/nfq_loop.moon
-- Boucle NFQUEUE générique : ouvre une queue, installe le callback,
-- tourne jusqu'à erreur. Factorisé pour être réutilisé par Q0 et Q1.
-- Le caller fournit le numéro de queue et la fonction de callback Lua.

{ :ffi, :libc, :libnfq } = require "ffi_defs"
{ :AF_INET } = require "config"
{ :log_info, :log_error } = require "log"

-- Constantes NFQUEUE
NFQNL_COPY_PACKET = 2   -- copie complète du paquet (payload inclus)
NF_DROP    = 0
NF_ACCEPT  = 1
NF_REPEAT  = 3           -- rejoue la règle (non utilisé ici)

-- Taille du buffer de lecture netlink (doit être > MTU + overhead netlink)
READ_BUF_SIZE = 65536

-- Sentinel : le callback a déjà posé son propre verdict (ex: Q1 avec payload patché)
VERDICT_DONE = -1

-- Lance la boucle sur une queue.
-- queue_num  : numéro de queue NFQUEUE (uint16)
-- callback   : function(qh_ptr, nfad, pkt_id) → NF_ACCEPT | NF_DROP
--              qh_ptr est le nfq_q_handle pour appeler nfq_set_verdict
-- Bloque jusqu'à erreur ou SIGINT.
run_queue = (queue_num, callback) ->
  log_info { action: "queue_open", queue: queue_num }

  h = libnfq.nfq_open!
  error "nfq_open() échoué" if h == nil

  -- bind_pf : attache le handle à la famille AF_INET
  -- Peut renvoyer une erreur si déjà bindé par un autre handle dans le process ;
  -- on ignore l'erreur (comportement historique de libnetfilter_queue).
  libnfq.nfq_bind_pf h, AF_INET

  -- Pointeur partagé entre la closure C et la closure Lua du callback
  qh_box = ffi.new "nfq_q_handle*[1]"

  -- Wrapper C minimal : extrait pkt_id et délègue au callback Lua
  c_callback = ffi.cast "nfq_callback", (qh, nfmsg, nfad, data) ->
    -- Extraction de l'id du paquet depuis le header nfq
    -- nfq_get_msg_packet_hdr retourne un pointeur vers nfqnl_msg_packet_hdr
    -- dont le premier champ packet_id est en big-endian.
    raw_hdr = libnfq.nfq_get_msg_packet_hdr nfad
    pkt_id  = libc.ntohl raw_hdr.packet_id

    ok, verdict = pcall callback, qh_box[0], nfad, pkt_id
    unless ok
      -- En cas d'exception Lua dans le callback, on accepte le paquet
      -- (fail-open) pour ne pas bloquer le réseau, et on log.
      log_error { action: "callback_exception", err: tostring verdict }
      verdict = NF_ACCEPT

    -- Si verdict == VERDICT_DONE, le callback a déjà appelé nfq_set_verdict
    -- (ex: Q1 qui envoie un payload modifié) → on ne repose pas de verdict.
    if verdict != VERDICT_DONE
      libnfq.nfq_set_verdict qh_box[0], pkt_id, verdict, 0, nil
    0   -- retour C : 0 = succès

  qh = libnfq.nfq_create_queue h, queue_num, c_callback, nil
  error "nfq_create_queue(#{queue_num}) échoué" if qh == nil

  qh_box[0] = qh

  -- Copie complète du paquet (payload + métadonnées L2)
  libnfq.nfq_set_mode qh, NFQNL_COPY_PACKET, READ_BUF_SIZE

  fd  = libnfq.nfq_fd h
  buf = ffi.new "char[65536]"

  log_info { action: "queue_listening", queue: queue_num, pid: tonumber(ffi.C.getpid and ffi.C.getpid() or 0) }

  while true
    rv = libc.read fd, buf, READ_BUF_SIZE
    if rv > 0
      libnfq.nfq_handle_packet h, buf, tonumber rv
    elseif rv == 0
      break   -- EOF inattendu
    else
      -- rv < 0 : EINTR (signal) → on continue, autre erreur → on sort
      -- errno 4 = EINTR
      break

  log_info { action: "queue_closed", queue: queue_num }
  libnfq.nfq_destroy_queue qh
  libnfq.nfq_close h
  c_callback\free!   -- libère le wrapper ffi.cast

-- Verdict helpers exposés pour les workers
{ :run_queue, :NF_ACCEPT, :NF_DROP, :VERDICT_DONE }
