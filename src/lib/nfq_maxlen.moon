-- src/lib/nfq_maxlen.moon
-- Longueur maximale de la file noyau des files NFQUEUE.
--
-- Le noyau dimensionne chaque file à NFQNL_QMAX_DEFAULT (1024 paquets) quand
-- libnetfilter_queue n'appelle pas nfq_set_queue_maxlen(). Dès qu'elle est
-- pleine, le noyau jette les paquets **avant** de les remettre au socket
-- userspace : c'est `queue_dropped` (colonne 6 de
-- /proc/net/netfilter/nfnetlink_queue), distinct de `queue_user_dropped`
-- (colonne 7, tampon netlink, cf. src/lib/nfq_rcvbuf.moon). La campagne
-- d-tune (docs/agents/perf.md §15) a mesuré que toute la perte sous charge
-- venait de cette file pleine à 1024.
--
-- Ce module demande donc une longueur explicite (clé `nfqueue.maxlen`, sinon
-- 4096 paquets, ou 1024 en mode RAM faible). Chaque paquet en attente occupe
-- de la mémoire noyau (skb + copie du payload) : à ~1,5 Ko par paquet, 4096
-- emplacements représentent ~6 Mio par file dans le pire cas.
--
-- Un échec de nfq_set_queue_maxlen (retour < 0) n'empêche **pas** la file de
-- démarrer : la valeur par défaut du noyau s'applique et un WARN le signale.

ffi = require "ffi"
{ :log_info, :log_warn, :log_debug } = require "log"

DEFAULT_MAXLEN = 4096   -- paquets
LOWMEM_MAXLEN  = 1024   -- paquets (NFQNL_QMAX_DEFAULT, profil RAM faible)

--- Longueur de file à demander.
-- `configured` (`nfqueue.maxlen`, en paquets) prime quand c'est un entier
-- strictement positif ; sinon 4096, ou 1024 en mode RAM faible.
-- @tparam number|string|nil configured Valeur de configuration
-- @tparam boolean is_lowmem Profil RAM faible actif
-- @treturn number Longueur demandée en paquets
resolve_maxlen = (configured, is_lowmem) ->
  v = tonumber configured
  return v if v and v > 0 and v % 1 == 0
  if is_lowmem then LOWMEM_MAXLEN else DEFAULT_MAXLEN

--- Vrai si la libnfq fournie expose nfq_set_queue_maxlen.
-- En test unitaire, `ffi_defs` est stubbé (libnfq sans cette fonction) : la
-- fonctionnalité est alors simplement désactivée (aucun log), plutôt que
-- d'échouer au démarrage d'une file.
-- @tparam table|nil libnfq Bibliothèque libnetfilter_queue
-- @treturn boolean
api_available = (libnfq) ->
  return false unless libnfq
  ok, fn = pcall -> libnfq.nfq_set_queue_maxlen
  ok and fn and true or false

--- Applique la longueur de file à une queue NFQUEUE.
-- @tparam table libnfq Bibliothèque libnetfilter_queue
-- @tparam cdata qh Handle de queue (nfq_q_handle)
-- @tparam number maxlen Longueur demandée en paquets
-- @treturn table|nil { maxlen, rc, ok }, nil si l'API n'est pas disponible
--   (stub de test)
apply_maxlen = (libnfq, qh, maxlen) ->
  return nil unless api_available libnfq
  rc = libnfq.nfq_set_queue_maxlen qh, maxlen
  { :maxlen, :rc, ok: rc >= 0 }

--- Applique et journalise la longueur de file d'une queue NFQUEUE.
-- INFO `queue_maxlen` (queue, maxlen) au succès ; WARN `queue_maxlen_failed`
-- (queue, maxlen, rc, errno) si le noyau refuse la valeur — la file démarre
-- quand même avec la longueur par défaut.
-- @tparam table|nil libnfq Bibliothèque libnetfilter_queue
-- @tparam table|nil libc Table libc (ffi.C en production, pour errno)
-- @tparam cdata qh Handle de queue (nfq_q_handle)
-- @tparam number queue_num Numéro de file (pour le log)
-- @tparam number|string|nil configured Valeur de `nfqueue.maxlen`
-- @tparam boolean is_lowmem Profil RAM faible actif
-- @treturn table|nil Résultat de apply_maxlen (nil si API indisponible)
configure = (libnfq, libc, qh, queue_num, configured, is_lowmem) ->
  maxlen = resolve_maxlen configured, is_lowmem
  res = apply_maxlen libnfq, qh, maxlen
  unless res
    log_debug -> { action: "queue_maxlen_unavailable", queue: queue_num }
    return nil
  if res.ok
    log_info -> { action: "queue_maxlen", queue: queue_num, maxlen: maxlen }
  else
    errno = nil
    if libc and libc.__errno_location
      ok, val = pcall -> tonumber libc.__errno_location()[0]
      errno = val if ok
    log_warn -> {
      action: "queue_maxlen_failed"
      queue: queue_num
      maxlen: maxlen
      rc: res.rc
      errno: errno
    }
  res

{ :DEFAULT_MAXLEN, :LOWMEM_MAXLEN, :resolve_maxlen, :api_available,
  :apply_maxlen, :configure }
