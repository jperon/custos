-- src/doh/h2_frames.moon
-- Utilitaires de lecture/écriture de frames HTTP/2 (RFC 7540).
-- Partagé entre worker_doh (serveur DoH) et upstream_doh_h2 (client DoH).

bit = require "bit"

H2_FRAME_DATA          = 0x0
H2_FRAME_HEADERS       = 0x1
H2_FRAME_SETTINGS      = 0x4
H2_FRAME_PING          = 0x6
H2_FRAME_GOAWAY        = 0x7
H2_FRAME_WINDOW_UPDATE = 0x8

H2_FLAG_END_STREAM  = 0x1
H2_FLAG_END_HEADERS = 0x4
H2_FLAG_ACK         = 0x1

--- Reçoit exactement n octets depuis conn (accumule si nécessaire).
-- @tparam  table  conn  Connexion avec méthode :receive(n).
-- @tparam  number n     Nombre d'octets attendus.
-- @treturn string|nil   Données reçues, ou nil + erreur.
h2_recv_exact = (conn, n) ->
  chunks = {}
  got = 0
  while got < n
    chunk, err = nil, nil
    for _ = 1, 50
      chunk, err = conn\receive n - got
      break if chunk
      break if err != "want_read_write"
    return nil, err unless chunk and #chunk > 0
    chunks[#chunks + 1] = chunk
    got += #chunk
  table.concat chunks

--- Lit une frame HTTP/2 complète depuis conn.
-- @treturn number ftype, number flags, number sid, string payload — ou nil + erreur.
h2_read_frame = (conn) ->
  hdr, err = h2_recv_exact conn, 9
  return nil, err unless hdr
  len   = hdr\byte(1) * 65536 + hdr\byte(2) * 256 + hdr\byte(3)
  ftype = hdr\byte(4)
  flags = hdr\byte(5)
  sid   = bit.band(
    bit.bor(
      bit.lshift(hdr\byte(6), 24),
      bit.lshift(hdr\byte(7), 16),
      bit.lshift(hdr\byte(8),  8),
      hdr\byte(9)
    ),
    0x7FFFFFFF
  )
  payload = if len > 0
    p, perr = h2_recv_exact conn, len
    return nil, perr unless p
    p
  else
    ""
  ftype, flags, sid, payload

--- Sérialise et envoie une frame HTTP/2 sur conn.
-- @tparam table  conn    Connexion avec méthode :send(data).
-- @tparam number ftype   Type de frame (H2_FRAME_*).
-- @tparam number flags   Flags (H2_FLAG_*).
-- @tparam number sid     Stream ID.
-- @tparam string payload Corps de la frame (peut être nil ou vide).
h2_write_frame = (conn, ftype, flags, sid, payload) ->
  payload = payload or ""
  n = #payload
  frame = string.char(
    bit.band(bit.rshift(n, 16), 0xFF),
    bit.band(bit.rshift(n,  8), 0xFF),
    bit.band(n,                 0xFF),
    ftype, flags,
    bit.band(bit.rshift(sid, 24), 0xFF),
    bit.band(bit.rshift(sid, 16), 0xFF),
    bit.band(bit.rshift(sid,  8), 0xFF),
    bit.band(sid,                 0xFF)
  ) .. payload
  conn\send frame

{
  :H2_FRAME_DATA, :H2_FRAME_HEADERS, :H2_FRAME_SETTINGS
  :H2_FRAME_PING, :H2_FRAME_GOAWAY, :H2_FRAME_WINDOW_UPDATE
  :H2_FLAG_END_STREAM, :H2_FLAG_END_HEADERS, :H2_FLAG_ACK
  :h2_recv_exact, :h2_read_frame, :h2_write_frame
}
