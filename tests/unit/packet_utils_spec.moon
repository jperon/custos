-- tests/unit/packet_utils_spec.moon
-- Helpers partagés de parsing IP/TCP pour les workers DNS.

ffi = require "ffi"
packet_utils = require "packet_utils"

make_ipv6_packet = (next_header=17, ext_header=44, ext_size=8) ->
  raw = ffi.new "uint8_t[?]", 40 + ext_size
  raw[0] = 0x60
  raw[2] = ext_size
  raw[3] = next_header
  raw[40] = ext_header
  raw[41] = ext_size - 8
  raw

describe "packet_utils", ->

  describe "mac2s", ->
    it "formate 6 octets en adresse MAC", ->
      assert.equals "aa:bb:cc:dd:ee:ff", packet_utils.mac2s "\170\187\204\221\238\255"

    it "formate des octets nuls", ->
      assert.equals "00:00:00:00:00:00", packet_utils.mac2s "\0\0\0\0\0\0"

    it "respecte l'offset 1-based", ->
      assert.equals "01:02:03:04:05:06", packet_utils.mac2s "XX\1\2\3\4\5\6", 3

  describe "skip_ipv6_ext_hdrs", ->
    it "renvoie directement UDP sans extension", ->
      raw = make_ipv6_packet 17
      proto, off = packet_utils.skip_ipv6_ext_hdrs ffi.cast("const uint8_t*", raw), 40, 17
      assert.equals 17, proto
      assert.equals 40, off

    it "saute un en-tête d'extension standard", ->
      raw = make_ipv6_packet 17, 44, 8
      raw[40] = 17
      proto, off = packet_utils.skip_ipv6_ext_hdrs ffi.cast("const uint8_t*", raw), 48, 44
      assert.equals 17, proto
      assert.equals 48, off

    it "saute plusieurs extensions jusqu'au L4", ->
      raw = ffi.new "uint8_t[56]", 0
      raw[0] = 0x60
      raw[2] = 16
      raw[3] = 44
      raw[40] = 44
      raw[41] = 0
      raw[48] = 17
      proto, off = packet_utils.skip_ipv6_ext_hdrs ffi.cast("const uint8_t*", raw), 56, 44
      assert.equals 17, proto
      assert.equals 56, off

    it "rejette un paquet tronqué", ->
      raw = make_ipv6_packet 17, 44, 8
      proto, off = packet_utils.skip_ipv6_ext_hdrs ffi.cast("const uint8_t*", raw), 48, 44
      assert.is_nil proto
      assert.is_nil off

  describe "dns_tcp_complete", ->
    it "accepte un buffer DNS-over-TCP complet", ->
      assert.is_true packet_utils.dns_tcp_complete string.char(0, 4) .. "abcd"

    it "rejette un buffer DNS-over-TCP incomplet", ->
      assert.is_false packet_utils.dns_tcp_complete string.char(0, 5) .. "abcd"

    it "rejette un buffer trop court", ->
      assert.is_false packet_utils.dns_tcp_complete string.char(0)

  describe "new_dns_tcp_stream", ->
    it "construit un réassembleur DNS TCP", ->
      stream = packet_utils.new_dns_tcp_stream!
      assert.is_function stream.feed
      assert.is_function stream.purge
