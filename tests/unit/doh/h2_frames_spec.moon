-- tests/unit/doh/h2_frames_spec.moon
-- Tests unitaires de doh.h2_frames (lecture/écriture de frames HTTP/2).

bit = require "bit"

make_conn_stub = (recv_data) ->
  recv_buf = recv_data
  recv_pos = 1
  sent_chunks = {}
  {
    receive: (n) =>
      if recv_pos > #recv_buf
        return nil, "eof"
      chunk = recv_buf\sub recv_pos, recv_pos + n - 1
      recv_pos += #chunk
      chunk
    send: (data) =>
      sent_chunks[#sent_chunks + 1] = data
      #data
    _sent: -> table.concat sent_chunks
  }

-- Encode une frame HTTP/2 brute (pour préparer les données de test).
encode_frame = (ftype, flags, sid, payload) ->
  payload = payload or ""
  n = #payload
  string.char(
    bit.band(bit.rshift(n, 16), 0xFF),
    bit.band(bit.rshift(n,  8), 0xFF),
    bit.band(n,                 0xFF),
    ftype, flags,
    bit.band(bit.rshift(sid, 24), 0xFF),
    bit.band(bit.rshift(sid, 16), 0xFF),
    bit.band(bit.rshift(sid,  8), 0xFF),
    bit.band(sid,                 0xFF)
  ) .. payload

describe "doh.h2_frames", ->
  local mod
  before_each -> mod = require "doh.h2_frames"

  describe "h2_read_frame", ->

    it "lit une frame SETTINGS vide", ->
      raw = encode_frame 0x4, 0, 0, ""
      conn = make_conn_stub raw
      ftype, flags, sid, payload = mod.h2_read_frame conn
      assert.equals 0x4, ftype
      assert.equals 0,   flags
      assert.equals 0,   sid
      assert.equals "",  payload

    it "lit une frame DATA avec payload", ->
      body = "hello"
      raw = encode_frame 0x0, 0x1, 1, body
      conn = make_conn_stub raw
      ftype, flags, sid, payload = mod.h2_read_frame conn
      assert.equals 0x0,   ftype
      assert.equals 0x1,   flags
      assert.equals 1,     sid
      assert.equals body,  payload

    it "retourne nil + err si connexion fermée prématurément", ->
      conn = make_conn_stub ""
      ftype, err = mod.h2_read_frame conn
      assert.is_nil ftype
      assert.is_not_nil err

  describe "h2_write_frame", ->

    it "sérialise correctement une frame SETTINGS vide", ->
      conn = make_conn_stub ""
      mod.h2_write_frame conn, 0x4, 0, 0, ""
      sent = conn._sent!
      assert.equals 9, #sent
      assert.equals 0x4, sent\byte 4
      assert.equals 0,   sent\byte 5

    it "inclut le payload dans la frame", ->
      payload = "abcde"
      conn = make_conn_stub ""
      mod.h2_write_frame conn, 0x0, 0x1, 1, payload
      sent = conn._sent!
      assert.equals 9 + #payload, #sent
      assert.equals #payload, sent\byte(3)
      assert.equals "abcde", sent\sub 10

  describe "constantes exportées", ->

    it "H2_FRAME_DATA = 0", ->
      assert.equals 0x0, mod.H2_FRAME_DATA

    it "H2_FLAG_END_STREAM = 0x1", ->
      assert.equals 0x1, mod.H2_FLAG_END_STREAM

    it "H2_FLAG_END_HEADERS = 0x4", ->
      assert.equals 0x4, mod.H2_FLAG_END_HEADERS

    it "H2_FLAG_ACK = 0x1", ->
      assert.equals 0x1, mod.H2_FLAG_ACK
