-- src/ipc.moon
-- Protocole IPC entre worker Q0 (questions) et worker Q1 (réponses).
-- Transport : pipe Unix anonyme créé avant fork().
-- Les messages sont des enregistrements binaires de taille fixe (43 octets).
-- L'atomicité est garantie par POSIX pour les écritures <= PIPE_BUF (4096).
--
-- Format du message (43 octets) :
--
--   Octet 0      : version/type (6 bits) + flags (2 bits)
--                  bits 6-0: message type/family
--                    0x41 ('A') & 0x7F = transaction IPv4 acceptée
--                    0x36 ('6') & 0x7F = transaction IPv6 acceptée
--                    0x52 ('R') & 0x7F = transaction IPv4 refusée (Q1 forge REFUSED+EDE)
--                    0x72 ('r') & 0x7F = transaction IPv6 refusée
--                    0x44 ('D') & 0x7F = transaction IPv4 DNS-seulement
--                    0x64 ('d') & 0x7F = transaction IPv6 DNS-seulement
--                  bit 7: RESOLVER_IPV6_FLAG — set if resolver is IPv6 (avoids false negatives)
--   Octets 1-2   : txid DNS (big-endian uint16)
--   Octets 3-18  : src_ip — 16 octets (IPv4 4 octets + 12 octets 0x00 ; IPv6 16 octets complets)
--   Octets 19-20 : src_port (big-endian uint16)
--   Octets 21-26 : adresse MAC source (6 octets, 0x00×6 si inconnue)
--   Octets 27-42 : resolver_ip — 16 octets (IPv4 4 octets + 12 octets 0x00 ; IPv6 16 octets)
--   → Total : 43 octets, largement sous PIPE_BUF → écriture atomique garantie

{ :ffi, :libc } = require "ffi_defs"
{ :IPC_PENDING_TTL } = require "config"
{ :log_warn } = require "log"

IPC_MSG_SIZE = 43
IPC_WRITE_RETRY_COUNT = 5

EAGAIN = 11
EWOULDBLOCK = 11

bit = require "bit"

AF_INET6 = 10
ipv6_ntop_buf = ffi.new "char[46]"

timespec_ptr_t = ffi.typeof "timespec_t[1]"

-- ── Constantes de type ───────────────────────────────────────────
MSG_IPV4         = 0x41   -- 'A' : transaction IPv4 autorisée
MSG_IPV6         = 0x36   -- '6' : transaction IPv6 autorisée
MSG_IPV4_REFUSED = 0x52   -- 'R' : transaction IPv4 refusée (Q1 doit transformer la réponse)
MSG_IPV6_REFUSED = 0x72   -- 'r' : transaction IPv6 refusée
MSG_IPV4_DNSONLY = 0x44   -- 'D' : transaction IPv4 DNS-seulement (pas d'injection nft)
MSG_IPV6_DNSONLY = 0x64   -- 'd' : transaction IPv6 DNS-seulement

-- Bit flag 0x80 : set when resolver is IPv6 (avoids false negatives for addrs like fd00::)
RESOLVER_IPV6_FLAG = 0x80

write_with_retry = (pipe_wfd, msg) ->
  -- timespec buffer for nanosleep between retries (20 ms)
  sleep_req = timespec_ptr_t!

  for i = 1, IPC_WRITE_RETRY_COUNT
    n = libc.write pipe_wfd, msg, IPC_MSG_SIZE
    return true if n == IPC_MSG_SIZE

    errno_p = libc.__errno_location!
    errno = if errno_p then errno_p[0] else 0

    -- If it's an unrecoverable error, log errno and abort immediately.
    if errno != EAGAIN and errno != EWOULDBLOCK
      log_warn { action: "ipc_write_syscall_failed", fd: pipe_wfd, errno: errno, attempt: i }
      return false

    -- Otherwise it's transient (EAGAIN/EWOULDBLOCK) — sleep a bit before retrying.
    sleep_req[0].tv_sec = 0
    sleep_req[0].tv_nsec = 20000000    -- 20 ms
    libc.nanosleep sleep_req, nil

  -- Exhausted retries — log final errno for debugging and return false.
  errno_p = libc.__errno_location!
  errno = if errno_p then errno_p[0] else 0
  log_warn { action: "ipc_write_failed_exhausted", fd: pipe_wfd, errno: errno, attempts: IPC_WRITE_RETRY_COUNT }
  false

-- ── Encodage (côté Q0) ───────────────────────────────────────────
--- Encode une transaction en binaire IPC_MSG_SIZE octets.
-- @tparam number      txid      Identifiant de transaction DNS (uint16)
-- @tparam string      ip_raw    4 octets (IPv4) ou 16 octets (IPv6) bruts (IP client)
-- @tparam number      src_port  Port source de la question DNS (uint16)
-- @tparam string|nil  mac_raw   6 octets MAC bruts (nil ou zeros si inconnu)
-- @tparam string      resolver_ip_raw 4 ou 16 octets bruts de l'IP resolver
-- @tparam boolean     refused   true si la transaction est refusée (Q1 spoofing REFUSED+EDE)
-- @tparam boolean     dnsonly   true si DNS autorisé mais pas d'injection nft
-- @treturn string message binaire de IPC_MSG_SIZE octets
encode_msg = (txid, ip_raw, src_port, mac_raw, resolver_ip_raw, refused, dnsonly) ->
  buf = ffi.new "uint8_t[43]"

  -- Type : encode à la fois le refus/dnsonly et la famille d'adresse (IPv4/IPv6)
  msg_type = if #ip_raw == 4
    if dnsonly then MSG_IPV4_DNSONLY
    elseif refused then MSG_IPV4_REFUSED
    else MSG_IPV4
  else
    if dnsonly then MSG_IPV6_DNSONLY
    elseif refused then MSG_IPV6_REFUSED
    else MSG_IPV6
  
  -- Set RESOLVER_IPV6_FLAG bit if resolver is IPv6
  msg_type = bit.bor msg_type, RESOLVER_IPV6_FLAG if #resolver_ip_raw == 16
  
  buf[0] = msg_type

  -- txid big-endian
  buf[1] = bit.rshift bit.band(txid, 0xFF00), 8
  buf[2] = bit.band txid, 0xFF

  -- IP source dans buf[3..18] (16 octets)
  -- IPv4 : 4 octets écrits, les 12 suivants restent à 0x00 (ffi.new initialise à zéro)
  -- IPv6 : 16 octets écrits exactement
  for i = 1, #ip_raw
    buf[2 + i] = ip_raw\byte i

  -- Port source big-endian dans buf[19..20]
  buf[19] = bit.rshift bit.band(src_port, 0xFF00), 8
  buf[20] = bit.band src_port, 0xFF

  -- MAC source dans buf[21..26] (6 octets, 0x00 si inconnu)
  if mac_raw and #mac_raw == 6
    for i = 1, 6
      buf[20 + i] = mac_raw\byte i
  -- else : buf déjà zéroïsé par ffi.new

  -- IP resolver dans buf[27..42] (16 octets)
  for i = 1, #resolver_ip_raw
    buf[26 + i] = resolver_ip_raw\byte i

  ffi.string buf, IPC_MSG_SIZE

--- Écrit un message IPC pour une transaction autorisée dans le pipe (côté Q0).
-- @tparam number     pipe_wfd fd d'écriture du pipe
-- @tparam number     txid     Identifiant de transaction DNS
-- @tparam string     ip_raw   4 ou 16 octets bruts de l'IP source (client)
-- @tparam number     src_port Port source
-- @tparam string|nil mac_raw  6 octets MAC bruts (nil si inconnu)
-- @tparam string     resolver_ip_raw 4 ou 16 octets bruts de l'IP resolver
-- @treturn boolean true si l'écriture est complète
write_msg = (pipe_wfd, txid, ip_raw, src_port, mac_raw, resolver_ip_raw) ->
  msg = encode_msg txid, ip_raw, src_port, mac_raw, resolver_ip_raw, false, false
  write_with_retry pipe_wfd, msg

--- Écrit un message IPC pour une transaction refusée dans le pipe (côté Q0).
-- Q1 intercèptera la réponse du serveur et la transformera en REFUSED+EDE.
-- @tparam number     pipe_wfd fd d'écriture du pipe
-- @tparam number     txid     Identifiant de transaction DNS
-- @tparam string     ip_raw   4 ou 16 octets bruts de l'IP source (client)
-- @tparam number     src_port Port source
-- @tparam string|nil mac_raw  6 octets MAC bruts (nil si inconnu)
-- @tparam string     resolver_ip_raw 4 ou 16 octets bruts de l'IP resolver
-- @treturn boolean true si l'écriture est complète
write_refused_msg = (pipe_wfd, txid, ip_raw, src_port, mac_raw, resolver_ip_raw) ->
  msg = encode_msg txid, ip_raw, src_port, mac_raw, resolver_ip_raw, true, false
  write_with_retry pipe_wfd, msg

--- Écrit un message IPC pour une transaction DNS-seulement dans le pipe (côté Q0).
-- Q1 laissera passer la réponse (avec patch TTL+EDE) mais n'injectera pas
-- les IPs dans les sets nft — les redirections HTTP restent actives.
-- @tparam number     pipe_wfd fd d'écriture du pipe
-- @tparam number     txid     Identifiant de transaction DNS
-- @tparam string     ip_raw   4 ou 16 octets bruts de l'IP source (client)
-- @tparam number     src_port Port source
-- @tparam string|nil mac_raw  6 octets MAC bruts (nil si inconnu)
-- @tparam string     resolver_ip_raw 4 ou 16 octets bruts de l'IP resolver
-- @treturn boolean true si l'écriture est complète
write_dnsonly_msg = (pipe_wfd, txid, ip_raw, src_port, mac_raw, resolver_ip_raw) ->
  msg = encode_msg txid, ip_raw, src_port, mac_raw, resolver_ip_raw, false, true
  write_with_retry pipe_wfd, msg

-- ── Décodage (côté Q1) ───────────────────────────────────────────
--- Décode un message binaire IPC en table.
-- @tparam  string    raw Message de IPC_MSG_SIZE octets
-- @treturn table|nil Table {txid, ip_str, src_port, resolver_ip_str, msg_type, mac_str, ipv4, refused} ou nil si invalide
decode_msg = (raw) ->
  return nil if #raw < IPC_MSG_SIZE

  msg_type_full = raw\byte 1
  msg_type      = bit.band msg_type_full, 0x7F  -- mask out RESOLVER_IPV6_FLAG
  resolver_ipv6 = (bit.band(msg_type_full, RESOLVER_IPV6_FLAG) != 0)
  
  txid     = bit.bor bit.lshift(raw\byte(2), 8), raw\byte(3)
  src_port = bit.bor bit.lshift(raw\byte(20), 8), raw\byte(21)

  ipv4    = (msg_type == MSG_IPV4 or msg_type == MSG_IPV4_REFUSED or msg_type == MSG_IPV4_DNSONLY)
  refused = (msg_type == MSG_IPV4_REFUSED or msg_type == MSG_IPV6_REFUSED)
  dnsonly = (msg_type == MSG_IPV4_DNSONLY or msg_type == MSG_IPV6_DNSONLY)

  ip_str = if ipv4
    "#{raw\byte 4}.#{raw\byte 5}.#{raw\byte 6}.#{raw\byte 7}"
  else
    -- IPv6 : utiliser inet_ntop pour obtenir la forme canonique compressée (fd00:28::a)
    -- identique à fmt_ipv6 dans parse/ndpi pour garantir la cohérence des clés pending.
    ip_bytes = ffi.new "uint8_t[16]"
    for i = 0, 15
      ip_bytes[i] = raw\byte 4 + i
    libc.inet_ntop AF_INET6, ip_bytes, ipv6_ntop_buf, 46
    ffi.string ipv6_ntop_buf

  resolver_ip_str = if resolver_ipv6
    resolver_ip_bytes = ffi.new "uint8_t[16]"
    for i = 0, 15
      resolver_ip_bytes[i] = raw\byte 28 + i
    libc.inet_ntop AF_INET6, resolver_ip_bytes, ipv6_ntop_buf, 46
    ffi.string ipv6_ntop_buf
  else
    "#{raw\byte 28}.#{raw\byte 29}.#{raw\byte 30}.#{raw\byte 31}"

  -- MAC : octets 21-26 (indices Lua 22-27)
  mac_str = string.format "%02x:%02x:%02x:%02x:%02x:%02x",
    raw\byte(22), raw\byte(23), raw\byte(24),
    raw\byte(25), raw\byte(26), raw\byte(27)

  { :txid, :ip_str, :src_port, :resolver_ip_str, :msg_type, :mac_str, :ipv4, :refused, :dnsonly }

-- ── Table des transactions en attente (côté Q1) ──────────────────
-- pending[key] = {expire: expire_time, refused: bool}
-- key = txid_hex .. ":" .. ip_str .. ":" .. port_str .. ":" .. resolver_ip_str
-- Accès O(1), purge paresseuse au moment du lookup.

pending = {}

make_key = (txid, ip_str, src_port, resolver_ip_str) ->
  string.format "%04x:%s:%d:%s", txid, ip_str, src_port, resolver_ip_str

--- Draine le pipe (lecture non-bloquante) et remplit la table pending.
-- Pour chaque message décodé, appelle on_msg(msg) si fourni (optionnel).
-- @tparam number        pipe_rfd fd de lecture du pipe (mode O_NONBLOCK requis)
-- @tparam function      now_fn   Fonction retournant l'epoch courant (seconde)
-- @tparam function|nil  on_msg   Callback appelé pour chaque message décodé
-- @treturn number nombre de messages absorbés
drain_pipe = (pipe_rfd, now_fn, on_msg) ->
  buf = ffi.new "uint8_t[?]", IPC_MSG_SIZE
  absorbed = 0

  while true
    n = libc.read pipe_rfd, buf, IPC_MSG_SIZE
    if n == 0
      log_warn { action: "ipc_pipe_eof", fd: pipe_rfd }   -- Q0 died
      break
    break if n < 0   -- EAGAIN / other transient error

    if n == IPC_MSG_SIZE
      raw = ffi.string buf, IPC_MSG_SIZE
      msg = decode_msg raw
      if msg
        key = make_key msg.txid, msg.ip_str, msg.src_port, msg.resolver_ip_str
        pending[key] = { expire: now_fn! + IPC_PENDING_TTL, refused: msg.refused, dnsonly: msg.dnsonly }
        absorbed += 1
        on_msg msg if on_msg

  absorbed

--- Vérifie si une transaction est en attente (et non expirée).
-- Purge l'entrée si elle est expirée (purge paresseuse).
-- @tparam number   txid     Identifiant de transaction DNS
-- @tparam string   ip_str   Adresse IP source (texte)
-- @tparam number   src_port Port source
-- @tparam string   resolver_ip_str Adresse IP du resolver (texte)
-- @tparam function now_fn   Fonction retournant l'epoch courant
-- @treturn boolean true si la transaction est présente et valide
is_pending = (txid, ip_str, src_port, resolver_ip_str, now_fn) ->
  key = make_key txid, ip_str, src_port, resolver_ip_str
  entry = pending[key]
  return false unless entry

  if now_fn! > entry.expire
    pending[key] = nil   -- purge paresseuse
    return false

  true

--- Retourne l'entrée pending d'une transaction, ou nil si absente/expirée.
-- Purge l'entrée si elle est expirée (purge paresseuse).
-- @tparam number   txid     Identifiant de transaction DNS
-- @tparam string   ip_str   Adresse IP source (texte)
-- @tparam number   src_port Port source
-- @tparam string   resolver_ip_str Adresse IP du resolver (texte)
-- @tparam function now_fn   Fonction retournant l'epoch courant
-- @treturn table|nil Table {expire, refused} ou nil si absent/expiré
get_pending_entry = (txid, ip_str, src_port, resolver_ip_str, now_fn) ->
  key = make_key txid, ip_str, src_port, resolver_ip_str
  entry = pending[key]
  return nil unless entry

  if now_fn! > entry.expire
    pending[key] = nil
    return nil

  entry

--- Retire une transaction de la table pending (une réponse par question).
-- @tparam number txid     Identifiant de transaction DNS
-- @tparam string ip_str   Adresse IP source (texte)
-- @tparam number src_port Port source
-- @tparam string resolver_ip_str Adresse IP du resolver (texte)
-- @treturn nil
consume = (txid, ip_str, src_port, resolver_ip_str) ->
  key = make_key txid, ip_str, src_port, resolver_ip_str
  pending[key] = nil

{ :encode_msg, :decode_msg, :write_msg, :write_refused_msg, :write_dnsonly_msg, :drain_pipe
  :is_pending, :get_pending_entry, :consume
  :MSG_IPV4, :MSG_IPV6, :MSG_IPV4_REFUSED, :MSG_IPV6_REFUSED
  :MSG_IPV4_DNSONLY, :MSG_IPV6_DNSONLY, :make_key }
