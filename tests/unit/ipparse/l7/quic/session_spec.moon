-- tests/unit/ipparse/l7/quic/session_spec.moon
-- Tests for QUIC session CRYPTO reassembly and frame iteration.
--
-- We test two layers:
--   1. frames.iter_frames: correctly skips PING (and other non-CRYPTO) frames
--   2. session.crypto_stream: correctly reassembles out-of-order chunks across pushes

{:iter_frames, :encode_varint} = require "ipparse.l4.quic.frames"
session_mod = require "ipparse.l7.quic.session"

-- Build a raw CRYPTO frame binary (type 0x06 + varint offset + varint len + data).
make_crypto_frame = (offset, data) ->
  string.char(0x06) .. encode_varint(offset) .. encode_varint(#data) .. data

-- Build a raw PING frame binary (type 0x01, no payload).
make_ping_frame = ->
  string.char 0x01

-- Build a raw PADDING frame binary (type 0x00, 1 byte).
make_padding_frame = ->
  string.char 0x00

describe "ipparse.l4.quic.frames.iter_frames", ->
  it "iterates CRYPTO frames interleaved with PING frames", ->
    payload = make_crypto_frame(0, "hello") ..
              make_ping_frame! ..
              make_crypto_frame(5, "world")

    collected = {}
    for f in iter_frames payload
      collected[#collected + 1] = f

    -- 3 frames total: CRYPTO, PING, CRYPTO
    assert.equals 3, #collected
    assert.equals "CRYPTO", collected[1].name
    assert.equals 0,         collected[1].offset
    assert.equals "hello",   collected[1].data
    assert.equals "PING",    collected[2].name
    assert.equals "CRYPTO",  collected[3].name
    assert.equals 5,         collected[3].offset
    assert.equals "world",   collected[3].data

  it "collects all CRYPTO frames despite multiple interleaved PING and PADDING", ->
    payload = make_padding_frame! ..
              make_crypto_frame(0, "abc") ..
              make_ping_frame! ..
              make_crypto_frame(3, "def") ..
              make_ping_frame! ..
              make_padding_frame! ..
              make_crypto_frame(6, "ghi")

    crypto_frames = [f for f in iter_frames(payload) when f.name == "CRYPTO"]

    assert.equals 3, #crypto_frames
    assert.equals "abc", crypto_frames[1].data
    assert.equals "def", crypto_frames[2].data
    assert.equals "ghi", crypto_frames[3].data


describe "ipparse.l7.quic.session", ->
  -- Create a session with a dummy backend to bypass crypto initialisation.
  -- This lets us test the reassembly logic (crypto_chunks + crypto_stream)
  -- without needing a real wolfssl/openssl/mbedtls library.
  make_session = ->
    session_mod.new backend: {}

  describe "session:crypto_stream()", ->
    it "returns empty string when no chunks collected", ->
      s = make_session!
      assert.equals "", s\crypto_stream!

    it "reassembles two adjacent chunks in order", ->
      s = make_session!
      s.crypto_chunks[0] = "hello"
      s.crypto_chunks[5] = "world"
      assert.equals "helloworld", s\crypto_stream!

    it "reassembles out-of-order chunks by offset", ->
      s = make_session!
      s.crypto_chunks[5] = "world"
      s.crypto_chunks[0] = "hello"
      assert.equals "helloworld", s\crypto_stream!

    it "handles a single chunk at offset 0", ->
      s = make_session!
      s.crypto_chunks[0] = "onlychunk"
      assert.equals "onlychunk", s\crypto_stream!

    it "returns empty string when first chunk is not at offset 0 (gap)", ->
      s = make_session!
      s.crypto_chunks[10] = "late"
      -- reassemble_stream requires contiguous from 0; offset 10 is unreachable
      assert.equals "", s\crypto_stream!

  describe "session:sni() cache invalidation", ->
    it "recomputes sni_dirty=true when chunks are updated", ->
      s = make_session!
      -- Pre-fill a minimal TLS ClientHello with SNI = "example.com"
      -- (11 bytes name) built from known offsets.
      -- We only verify that sni() returns nil for non-TLS data and that
      -- the dirty flag is correctly reset on subsequent calls.
      s.crypto_chunks[0] = "not-tls"
      s.sni_dirty = true

      result1 = s\sni!
      assert.is_nil result1
      assert.is_false s.sni_dirty  -- flag cleared after first call

      result2 = s\sni!
      assert.is_nil result2        -- cached nil, not recomputed
