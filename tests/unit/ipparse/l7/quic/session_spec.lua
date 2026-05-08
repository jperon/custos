local iter_frames, encode_varint
do
  local _obj_0 = require("ipparse.l4.quic.frames")
  iter_frames, encode_varint = _obj_0.iter_frames, _obj_0.encode_varint
end
local session_mod = require("ipparse.l7.quic.session")
local make_crypto_frame
make_crypto_frame = function(offset, data)
  return string.char(0x06) .. encode_varint(offset) .. encode_varint(#data) .. data
end
local make_ping_frame
make_ping_frame = function()
  return string.char(0x01)
end
local make_padding_frame
make_padding_frame = function()
  return string.char(0x00)
end
describe("ipparse.l4.quic.frames.iter_frames", function()
  it("iterates CRYPTO frames interleaved with PING frames", function()
    local payload = make_crypto_frame(0, "hello") .. make_ping_frame() .. make_crypto_frame(5, "world")
    local collected = { }
    for f in iter_frames(payload) do
      collected[#collected + 1] = f
    end
    assert.equals(3, #collected)
    assert.equals("CRYPTO", collected[1].name)
    assert.equals(0, collected[1].offset)
    assert.equals("hello", collected[1].data)
    assert.equals("PING", collected[2].name)
    assert.equals("CRYPTO", collected[3].name)
    assert.equals(5, collected[3].offset)
    return assert.equals("world", collected[3].data)
  end)
  return it("collects all CRYPTO frames despite multiple interleaved PING and PADDING", function()
    local payload = make_padding_frame() .. make_crypto_frame(0, "abc") .. make_ping_frame() .. make_crypto_frame(3, "def") .. make_ping_frame() .. make_padding_frame() .. make_crypto_frame(6, "ghi")
    local crypto_frames
    do
      local _accum_0 = { }
      local _len_0 = 1
      for f in iter_frames(payload) do
        if f.name == "CRYPTO" then
          _accum_0[_len_0] = f
          _len_0 = _len_0 + 1
        end
      end
      crypto_frames = _accum_0
    end
    assert.equals(3, #crypto_frames)
    assert.equals("abc", crypto_frames[1].data)
    assert.equals("def", crypto_frames[2].data)
    return assert.equals("ghi", crypto_frames[3].data)
  end)
end)
return describe("ipparse.l7.quic.session", function()
  local make_session
  make_session = function()
    return session_mod.new({
      backend = { }
    })
  end
  describe("session:crypto_stream()", function()
    it("returns empty string when no chunks collected", function()
      local s = make_session()
      return assert.equals("", s:crypto_stream())
    end)
    it("reassembles two adjacent chunks in order", function()
      local s = make_session()
      s.crypto_chunks[0] = "hello"
      s.crypto_chunks[5] = "world"
      return assert.equals("helloworld", s:crypto_stream())
    end)
    it("reassembles out-of-order chunks by offset", function()
      local s = make_session()
      s.crypto_chunks[5] = "world"
      s.crypto_chunks[0] = "hello"
      return assert.equals("helloworld", s:crypto_stream())
    end)
    it("handles a single chunk at offset 0", function()
      local s = make_session()
      s.crypto_chunks[0] = "onlychunk"
      return assert.equals("onlychunk", s:crypto_stream())
    end)
    return it("returns empty string when first chunk is not at offset 0 (gap)", function()
      local s = make_session()
      s.crypto_chunks[10] = "late"
      return assert.equals("", s:crypto_stream())
    end)
  end)
  return describe("session:sni() cache invalidation", function()
    return it("recomputes sni_dirty=true when chunks are updated", function()
      local s = make_session()
      s.crypto_chunks[0] = "not-tls"
      s.sni_dirty = true
      local result1 = s:sni()
      assert.is_nil(result1)
      assert.is_false(s.sni_dirty)
      local result2 = s:sni()
      return assert.is_nil(result2)
    end)
  end)
end)
