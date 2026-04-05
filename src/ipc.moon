-- src/ipc.moon
-- Protocole IPC entre worker Q0 (questions) et worker Q1 (réponses).
-- Transport : pipe Unix anonyme créé avant fork().
-- Les messages sont des enregistrements binaires de taille fixe IPC_MSG_SIZE.
-- L'atomicité est garantie par POSIX pour les écritures <= PIPE_BUF (4096).
--
-- Format du message (21 octets) :
--
--   Octet 0      : version/type
--                    0x41 ('A') = transaction IPv4 acceptée
--                    0x36 ('6') = transaction IPv6 acceptée
--   Octets 1-2   : txid DNS (big-endian uint16)
--   Octets 3-18  : src_ip — 16 octets (IPv4 4 octets + 12 octets 0x00 ; IPv6 16 octets complets)
--   Octets 19-20 : src_port (big-endian uint16)
--   → Total : 21 octets, largement sous PIPE_BUF → écriture atomique garantie

{ :ffi, :libc } = require "ffi_defs"
{ :IPC_MSG_SIZE, :IPC_PENDING_TTL } = require "config"

bit = require "bit"

-- ── Constantes de type ───────────────────────────────────────────
MSG_IPV4 = 0x41   -- 'A'
MSG_IPV6 = 0x36   -- '6'

-- ── Encodage (côté Q0) ───────────────────────────────────────────
-- Encode une transaction acceptée dans un buffer ffi de IPC_MSG_SIZE octets.
-- ip_raw : string Lua (4 octets IPv4 ou 16 octets IPv6)
-- Retourne la string binaire à écrire dans le pipe.
encode_msg = (txid, ip_raw, src_port) ->
  buf = ffi.new "uint8_t[21]"

  -- Type
  buf[0] = #ip_raw == 4 and MSG_IPV4 or MSG_IPV6

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

  ffi.string buf, IPC_MSG_SIZE

-- Écrit un message dans le pipe (côté Q0).
-- pipe_wfd : fd d'écriture du pipe
write_msg = (pipe_wfd, txid, ip_raw, src_port) ->
  msg = encode_msg txid, ip_raw, src_port
  n = libc.write pipe_wfd, msg, IPC_MSG_SIZE
  n == IPC_MSG_SIZE

-- ── Décodage (côté Q1) ───────────────────────────────────────────
-- Décode un message brut (string 16 octets) en table.
decode_msg = (raw) ->
  return nil if #raw < IPC_MSG_SIZE

  msg_type = raw\byte 1
  txid     = bit.bor bit.lshift(raw\byte(2), 8), raw\byte(3)
  src_port = bit.bor bit.lshift(raw\byte(20), 8), raw\byte(21)

  ip_str = if msg_type == MSG_IPV4
    "#{raw\byte 4}.#{raw\byte 5}.#{raw\byte 6}.#{raw\byte 7}"
  else
    -- IPv6 : 16 octets complets dans raw\byte(4..19)
    groups = for g = 0, 7
      string.format "%x", bit.bor(bit.lshift(raw\byte(4 + g*2), 8), raw\byte(5 + g*2))
    table.concat groups, ":"

  { :txid, :ip_str, :src_port, :msg_type }

-- ── Table des transactions en attente (côté Q1) ──────────────────
-- pending[key] = expire_time
-- key = txid_hex .. ":" .. ip_str .. ":" .. port_str
-- Accès O(1), purge paresseuse au moment du lookup.

pending = {}

make_key = (txid, ip_str, src_port) ->
  string.format "%04x:%s:%d", txid, ip_str, src_port

-- Draine le pipe (lecture non-bloquante) et remplit la table pending.
-- pipe_rfd : fd de lecture du pipe (doit être en mode O_NONBLOCK)
-- now_fn   : fonction retournant l'epoch courant (injectée pour testabilité)
drain_pipe = (pipe_rfd, now_fn) ->
  buf = ffi.new "uint8_t[16]"
  absorbed = 0

  while true
    n = libc.read pipe_rfd, buf, IPC_MSG_SIZE
    break if n <= 0   -- EAGAIN ou erreur → pipe vide

    if n == IPC_MSG_SIZE
      raw = ffi.string buf, IPC_MSG_SIZE
      msg = decode_msg raw
      if msg
        key = make_key msg.txid, msg.ip_str, msg.src_port
        pending[key] = now_fn! + IPC_PENDING_TTL
        absorbed += 1

  absorbed

-- Vérifie si une transaction est dans la table (et non expirée).
-- Purge l'entrée si expirée (purge paresseuse).
is_pending = (txid, ip_str, src_port, now_fn) ->
  key = make_key txid, ip_str, src_port
  expire = pending[key]
  return false unless expire

  if now_fn! > expire
    pending[key] = nil   -- purge paresseuse
    return false

  true

-- Retire une transaction (une fois la réponse traitée)
consume = (txid, ip_str, src_port) ->
  key = make_key txid, ip_str, src_port
  pending[key] = nil

{ :encode_msg, :decode_msg, :write_msg, :drain_pipe, :is_pending, :consume
  :MSG_IPV4, :MSG_IPV6, :make_key }
