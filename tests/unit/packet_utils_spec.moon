-- tests/unit/packet_utils_spec.moon
-- Helpers partagés de parsing IP/TCP pour les workers DNS.

ffi = require "ffi"
packet_utils = require "packet_utils"
{ :s2ip } = require "ipparse.l3.ip"
sp = require("ipparse.lib.pack_compat").pack

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

    it "gère l'Authentication Header (taille en multiples de 4)", ->
      -- AH (next_header 51) : ext_size = (hdrlen + 2) * 4, ici (0+2)*4 = 8.
      raw = ffi.new "uint8_t[48]", 0
      raw[0]  = 0x60
      raw[40] = 17  -- next header après l'AH : UDP
      raw[41] = 0   -- hdrlen AH → 8 octets
      proto, off = packet_utils.skip_ipv6_ext_hdrs ffi.cast("const uint8_t*", raw), 48, 51
      assert.equals 17, proto
      assert.equals 48, off

    it "rejette quand l'octet de taille d'extension dépasse la longueur", ->
      -- Header d'extension présent mais len ne couvre pas off+2 (lecture impossible).
      raw = make_ipv6_packet 17, 44, 8
      proto, off = packet_utils.skip_ipv6_ext_hdrs ffi.cast("const uint8_t*", raw), 41, 44
      assert.is_nil proto
      assert.is_nil off

    it "rejette une extension chaînée qui déborde du paquet", ->
      -- ext_size annoncé = (10+1)*8 = 88 octets, bien au-delà des 48 du buffer.
      raw = ffi.new "uint8_t[48]", 0
      raw[0]  = 0x60
      raw[40] = 17
      raw[41] = 10
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

  -- Parsing L3/L4/L7 commun à worker_questions et worker_responses.
  describe "parse_dns_packet", ->
    dns_query = "\xab\xcd\1\0\0\1\0\0\0\0\0\0\7example\3com\0\0\1\0\1"
    ipv4_udp = (dns) ->
      udp_len = 8 + #dns
      total = 20 + udp_len
      hdr = sp ">B B H H H B B H", 0x45, 0, total, 0x1234, 0, 64, 17, 0
      hdr ..= s2ip("192.0.2.10") .. s2ip("1.1.1.1")
      hdr .. sp(">H H H H", 5353, 53, udp_len, 0) .. dns
    ipv4_syn = ->
      hdr = sp ">B B H H H B B H", 0x45, 0, 40, 0x1234, 0, 64, 6, 0
      hdr ..= s2ip("192.0.2.10") .. s2ip("1.1.1.1")
      hdr .. sp ">H H I I B B H H H", 5353, 53, 1, 0, 0x50, 0x02, 8192, 0, 0

    it "décode un paquet UDP/IPv4 jusqu'au message DNS", ->
      stream = packet_utils.new_dns_tcp_stream!
      ip, l4, dns_msg, dns_raw, ip_ihl = packet_utils.parse_dns_packet ipv4_udp(dns_query), stream
      assert.equals 4, ip.version
      assert.equals "udp", l4.proto
      assert.equals 0xabcd, dns_msg.header.id
      assert.equals dns_query, dns_raw
      assert.equals 20, ip_ihl

    it "renvoie parse_failed sur un paquet tronqué", ->
      stream = packet_utils.new_dns_tcp_stream!
      ip, status = packet_utils.parse_dns_packet "\x45\x00", stream
      assert.is_nil ip
      assert.equals "parse_failed", status

    it "renvoie tcp_control pour un SYN sans charge utile", ->
      stream = packet_utils.new_dns_tcp_stream!
      ip, status = packet_utils.parse_dns_packet ipv4_syn!, stream
      assert.is_nil ip
      assert.equals "tcp_control", status
