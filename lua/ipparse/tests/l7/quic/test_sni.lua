local util = require("ipparse.lib.util")
local test
test = util.test
local sp, su
do
  local _obj_0 = require("ipparse.lib.pack_compat")
  sp, su = _obj_0.pack, _obj_0.unpack
end
local hex_to_bin
hex_to_bin = require("ipparse.lib.hkdf").hex_to_bin
local quic_l7 = require("ipparse.l7.quic")
local reassemble_crypto, sni_from_tls, sni_from_frames, sni_from_plaintext
reassemble_crypto, sni_from_tls, sni_from_frames, sni_from_plaintext = quic_l7.reassemble_crypto, quic_l7.sni_from_tls, quic_l7.sni_from_frames, quic_l7.sni_from_plaintext
local make_hs
make_hs = function(hs_type, body)
  local n = #body
  return sp(">BBH", hs_type, math.floor(n / 65536), n % 65536) .. body
end
local make_ch_body
make_ch_body = function(extensions_bin)
  local client_random = string.rep("\x00", 32)
  local ciphers = "\x13\x01"
  local compressions = "\x00"
  return sp(">H c32 s1 s2 s1 s2", 0x0303, client_random, "", ciphers, compressions, extensions_bin)
end
local make_sni_ext
make_sni_ext = function(hostname)
  local entry = sp(">B s2", 0x00, hostname)
  local sni_data = sp(">s2", entry)
  return sp(">H s2", 0x0000, sni_data)
end
local make_ext
make_ext = function(ext_type)
  return sp(">H s2", ext_type, "")
end
test("reassemble_crypto: empty list -> empty string", function()
  return assert(reassemble_crypto({ }) == "")
end)
test("reassemble_crypto: single CRYPTO frame", function()
  local frames = {
    {
      name = "CRYPTO",
      offset = 0,
      data = "hello"
    }
  }
  return assert(reassemble_crypto(frames) == "hello")
end)
test("reassemble_crypto: two frames in order", function()
  local frames = {
    {
      name = "CRYPTO",
      offset = 0,
      data = "foo"
    },
    {
      name = "CRYPTO",
      offset = 3,
      data = "bar"
    }
  }
  return assert(reassemble_crypto(frames) == "foobar")
end)
test("reassemble_crypto: two frames out of order", function()
  local frames = {
    {
      name = "CRYPTO",
      offset = 5,
      data = "world"
    },
    {
      name = "CRYPTO",
      offset = 0,
      data = "hello"
    }
  }
  return assert(reassemble_crypto(frames) == "helloworld")
end)
test("reassemble_crypto: non-CRYPTO frames are ignored", function()
  local frames = {
    {
      name = "PADDING",
      offset = 0,
      data = "\x00\x00"
    },
    {
      name = "CRYPTO",
      offset = 0,
      data = "data"
    },
    {
      name = "ACK",
      offset = 0,
      data = "ack"
    }
  }
  return assert(reassemble_crypto(frames) == "data")
end)
test("reassemble_crypto: retransmissions with same offsets are deduplicated", function()
  local frames = {
    {
      name = "CRYPTO",
      offset = 0,
      data = "hello"
    },
    {
      name = "CRYPTO",
      offset = 0,
      data = "hello"
    },
    {
      name = "CRYPTO",
      offset = 5,
      data = "world"
    }
  }
  return assert(reassemble_crypto(frames) == "helloworld")
end)
test("sni_from_tls: empty data -> nil", function()
  return assert(sni_from_tls("") == nil)
end)
test("sni_from_tls: ServerHello (type 2) -> nil", function()
  local tls = make_hs(0x02, make_ch_body(""))
  return assert(sni_from_tls(tls) == nil)
end)
test("sni_from_tls: ClientHello without extensions -> nil", function()
  local tls = make_hs(0x01, make_ch_body(""))
  return assert(sni_from_tls(tls) == nil)
end)
test("sni_from_tls: ClientHello with SNI -> hostname", function()
  local tls = make_hs(0x01, make_ch_body(make_sni_ext("test.example")))
  return assert(sni_from_tls(tls) == "test.example", "expected 'test.example', got: " .. tostring(tostring(sni_from_tls(tls))))
end)
test("sni_from_tls: ClientHello with SNI not first extension -> correct SNI", function()
  local ext_other = make_ext(0x002b)
  local tls = make_hs(0x01, make_ch_body((ext_other .. make_sni_ext("alt.example"))))
  return assert(sni_from_tls(tls) == "alt.example", "expected 'alt.example', got: " .. tostring(tostring(sni_from_tls(tls))))
end)
local PLAINTEXT_HEX = table.concat({
  "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c",
  "00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006",
  "001d0017001800100007000504616c706e000500050100000000003300260024001d00209370b2c9caa4",
  "7fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b0003020304000d0010000e040305",
  "0306030203080408050806002d00020101001c00024001003900320408ffffffffffffffff05048000ff",
  "ff07048000ffff0801100104800075300901100f088394c8f03e51570806048000ffff"
})
test("sni_from_plaintext: RFC 9001 §A.2 payload -> 'example.com'", function()
  local plaintext = hex_to_bin(PLAINTEXT_HEX)
  local sni = sni_from_plaintext(plaintext)
  return assert(sni == "example.com", "expected 'example.com', got: " .. tostring(tostring(sni)))
end)
return util.summary("l7.quic.sni")
