-- src/lib/nfq_rcvbuf.moon
-- Taille du tampon de réception netlink des files NFQUEUE.
--
-- libnetfilter_queue crée son socket netlink sans setsockopt(SO_RCVBUF) : il
-- garde le défaut noyau (~208 Ko, `net.core.rmem_default`), soit ~140 paquets
-- de 1,5 Ko. Quand le résolveur répond par rafales, le noyau ne peut plus
-- remettre les paquets au socket et les jette : c'est `queue_user_dropped`
-- (colonne 7 de /proc/net/netfilter/nfnetlink_queue), pas `queue_dropped`
-- (cf. docs/agents/perf.md §5 et §13.5).
--
-- Ce module demande donc une taille explicite (clé `nfqueue.rcvbuf`, sinon
-- 4 Mio, ou 512 Kio en mode RAM faible), relit la valeur effective avec
-- getsockopt (le noyau double la valeur demandée et la borne par
-- `net.core.rmem_max`) et tente SO_RCVBUFFORCE quand la valeur obtenue reste
-- inférieure à la demande. SO_RCVBUFFORCE contourne `rmem_max` mais exige
-- CAP_NET_ADMIN : sans lui l'appel échoue (EPERM) et on garde la valeur
-- bornée, signalée par un WARN.
--
-- NETLINK_NO_ENOBUFS n'est **pas** activé : il ferait taire l'erreur ENOBUFS
-- au lieu de la traiter, en masquant la perte de paquets (même raisonnement
-- que docs/agents/perf.md §3.3).

ffi = require "ffi"
{ :log_info, :log_warn, :log_debug } = require "log"

SOL_SOCKET     = 1
SO_RCVBUF      = 8
SO_RCVBUFFORCE = 33   -- Linux : comme SO_RCVBUF sans borne net.core.rmem_max

DEFAULT_RCVBUF = 4 * 1024 * 1024   -- 4 Mio
LOWMEM_RCVBUF  = 512 * 1024        -- 512 Kio (profil RAM faible)

--- Taille de tampon à demander.
-- `configured` (`nfqueue.rcvbuf`, en octets) prime quand il est > 0 ; sinon
-- 4 Mio, ou 512 Kio en mode RAM faible.
-- @tparam number|string|nil configured Valeur de configuration
-- @tparam boolean is_lowmem Profil RAM faible actif
-- @treturn number Taille demandée en octets
resolve_requested = (configured, is_lowmem) ->
  v = tonumber configured
  return v if v and v > 0
  if is_lowmem then LOWMEM_RCVBUF else DEFAULT_RCVBUF

--- Vrai si le libc fourni expose l'API socket FFI nécessaire.
-- En test unitaire, `ffi_defs` est stubbé et les cdefs POSIX peuvent manquer :
-- la fonctionnalité est alors simplement désactivée (aucun log), plutôt que
-- d'échouer au démarrage d'une file.
-- @tparam table|nil libc Table libc (ffi.C en production)
-- @treturn boolean
socket_api_available = (libc) ->
  return false unless libc
  for name in *{ "setsockopt", "getsockopt" }
    ok, fn = pcall -> libc[name]
    return false unless ok and fn
  pcall(-> ffi.sizeof "socklen_t") and true or false

--- Relit la taille effective du tampon de réception.
-- @tparam table libc Table libc
-- @tparam number fd fd netlink
-- @treturn number|nil Valeur obtenue (octets), nil si getsockopt échoue
read_back = (libc, fd) ->
  val = ffi.new "int[1]", 0
  len = ffi.new "socklen_t[1]", ffi.sizeof "int"
  rc = libc.getsockopt fd, SOL_SOCKET, SO_RCVBUF, val, len
  return nil unless rc == 0
  tonumber val[0]

--- Règle SO_RCVBUF sur un fd netlink et rend la valeur effective.
-- Tente SO_RCVBUFFORCE si la valeur relue est inférieure à la demande (le
-- noyau a borné par `rmem_max`) ; un échec de FORCE (EPERM sans
-- CAP_NET_ADMIN) laisse la valeur bornée.
-- @tparam table libc Table libc
-- @tparam number fd fd netlink
-- @tparam number requested Taille demandée (octets)
-- @treturn table|nil { requested, obtained, forced, error } ; nil si l'API
--   socket n'est pas disponible (stub de test)
apply_rcvbuf = (libc, fd, requested) ->
  return nil unless socket_api_available libc
  val = ffi.new "int[1]", requested
  rc = libc.setsockopt fd, SOL_SOCKET, SO_RCVBUF, val, ffi.sizeof "int"
  unless rc == 0
    return {
      :requested
      obtained: nil
      forced: false
      error: tonumber libc.__errno_location()[0]
    }
  res = { :requested, obtained: read_back(libc, fd), forced: false, error: nil }
  if res.obtained and res.obtained < requested
    rc_force = libc.setsockopt fd, SOL_SOCKET, SO_RCVBUFFORCE, val, ffi.sizeof "int"
    if rc_force == 0
      got = read_back libc, fd
      if got and got >= requested
        res.obtained = got
        res.forced = true
  res

--- Applique et journalise la taille du tampon d'une file NFQUEUE.
-- INFO `queue_rcvbuf` avec la valeur effective (et `forced`), WARN
-- `queue_rcvbuf_below_requested` si le noyau/FORCE n'a pas accordé la
-- demande, WARN `queue_rcvbuf_failed` si setsockopt échoue.
-- @tparam table|nil libc Table libc (ffi.C en production)
-- @tparam number fd fd netlink (libnfq.nfq_fd)
-- @tparam number queue_num Numéro de file (pour le log)
-- @tparam number|string|nil configured Valeur de `nfqueue.rcvbuf`
-- @tparam boolean is_lowmem Profil RAM faible actif
-- @treturn table|nil Résultat de apply_rcvbuf (nil si API indisponible)
configure = (libc, fd, queue_num, configured, is_lowmem) ->
  requested = resolve_requested configured, is_lowmem
  res = apply_rcvbuf libc, fd, requested
  unless res
    log_debug -> { action: "queue_rcvbuf_unavailable", queue: queue_num }
    return nil
  if res.obtained
    log_info -> {
      action: "queue_rcvbuf"
      queue: queue_num
      requested: res.requested
      obtained: res.obtained
      forced: res.forced
    }
    if res.obtained < res.requested
      log_warn -> {
        action: "queue_rcvbuf_below_requested"
        queue: queue_num
        requested: res.requested
        obtained: res.obtained
        forced: res.forced
      }
  else
    log_warn -> {
      action: "queue_rcvbuf_failed"
      queue: queue_num
      requested: res.requested
      errno: res.error
    }
  res

{ :SOL_SOCKET, :SO_RCVBUF, :SO_RCVBUFFORCE, :DEFAULT_RCVBUF, :LOWMEM_RCVBUF,
  :resolve_requested, :socket_api_available, :read_back, :apply_rcvbuf, :configure }
