-- tests/unit/worker_reject_forge_spec.moon
-- T8 : forge des rejets TCP RST / ICMP admin-prohibited et verdicts de
-- handle_reject. Faux libnfq (nfq_get_payload / nfq_set_verdict) restauré
-- en teardown.

ffi = require "ffi"
bit = require "bit"
sp  = require("ipparse.lib.pack_compat").pack
{ :s2ip } = require "ipparse.l3.ip"
ip_mod  = require "ipparse.l3.ip"
tcp_mod = require "ipparse.l4.tcp"

STUB_KEYS = { "ffi_defs", "worker_reject" }
saved = {}

SRC4 = "10.0.0.1"
DST4 = "192.0.2.1"
SRC6 = "2001:db8::1"
DST6 = "2001:db8::2"

ipv4_tcp = (seq=1000, sport=12345, dport=80, payload="") ->
  total = 20 + 20 + #payload
  sp(">B B H H H B B H", 0x45, 0, total, 0x1234, 0x4000, 64, 6, 0) ..
    s2ip(SRC4) .. s2ip(DST4) ..
    sp(">H H I4 I4 B B H H H", sport, dport, seq, 7, 0x50, 0x02, 8192, 0, 0) ..
    payload

ipv6_tcp = (seq=2000, sport=12345, dport=443, payload="") ->
  payload_len = 20 + #payload
  string.char(0x60, 0, 0, 0) .. sp(">H B B", payload_len, 6, 64) ..
    s2ip(SRC6) .. s2ip(DST6) ..
    sp(">H H I4 I4 B B H H H", sport, dport, seq, 8, 0x50, 0x02, 8192, 0, 0) ..
    payload

ipv4_udp = (payload="", dport=33434) ->
  udp_len = 8 + #payload
  total = 20 + udp_len
  sp(">B B H H H B B H", 0x45, 0, total, 0x1234, 0x4000, 64, 17, 0) ..
    s2ip(SRC4) .. s2ip(DST4) ..
    sp(">H H H H", 50000, dport, udp_len, 0) .. payload

ipv6_udp = (payload="") ->
  udp_len = 8 + #payload
  string.char(0x60, 0, 0, 0) .. sp(">H B B", udp_len, 17, 64) ..
    s2ip(SRC6) .. s2ip(DST6) ..
    sp(">H H H H", 50000, 33434, udp_len, 0) .. payload

-- Checksums indépendants (RFC 1071 / 793 / 4443).
ones_sum = (s) ->
  sum = 0
  i = 1
  while i + 1 <= #s
    sum += s\byte(i) * 256 + s\byte(i + 1)
    i += 2
  sum += s\byte(i) * 256 if i == #s
  sum

fold16 = (sum) ->
  while bit.rshift(sum, 16) != 0
    sum = bit.band(sum, 0xFFFF) + bit.rshift(sum, 16)
  sum

ok_sum = (parts) ->
  total = 0
  total += ones_sum p for p in *parts
  fold16(total) == 0xFFFF

pseudo6 = (src6, dst6, payload, proto) ->
  src6 .. dst6 .. sp(">I4", #payload) .. "\0\0\0" .. string.char(proto)

describe "worker_reject forge", ->

  wr = nil
  payload = ""
  verdicts = {}

  before_each ->
    saved[k] = package.loaded[k] for k in *STUB_KEYS
    payload = ""
    verdicts = {}

    package.loaded["ffi_defs"] = {
      :ffi
      libc: ffi.C
      libnfq: {
        nfq_get_payload: (nfad, out) ->
          return 0 if #payload == 0
          buf = ffi.new "uint8_t[?]", #payload
          ffi.copy buf, payload
          out[0] = ffi.cast "unsigned char*", buf
          #payload
        nfq_set_verdict: (qh, id, verdict, len, ptr) ->
          verdicts[#verdicts + 1] = {
            :id, :verdict, :len
            data: (len > 0 and ptr != nil) and ffi.string(ptr, len) or nil
          }
          0
      }
    }
    package.loaded["worker_reject"] = nil
    wr = require "worker_reject"

  after_each ->
    for k in *STUB_KEYS
      package.loaded[k] = saved[k]

  parse4 = (raw) ->
    ip, _ = ip_mod.parse raw, 1
    tcp, _ = tcp_mod.parse raw, ip.data_off
    ip, tcp

  parse6 = (raw) ->
    ip, _ = ip_mod.parse raw, 1
    tcp, _ = tcp_mod.parse raw, ip.data_off
    ip, tcp

  describe "forge_tcp_rst", ->
    it "IPv4 : swap L3/L4, RST+ACK, ack = seq+1, checksums valides", ->
      raw = ipv4_tcp 1000, 12345, 80
      ip, tcp = parse4 raw
      forged = wr.forge_tcp_rst ip, tcp
      fip, ftcp = parse4 forged
      assert.equals 4, fip.version
      assert.equals 20 + 20, fip.total_len
      assert.equals DST4, require("ipparse.l3.ip").ip2s fip.src
      assert.equals SRC4, require("ipparse.l3.ip").ip2s fip.dst
      assert.equals 64, fip.ttl
      assert.equals 6, fip.protocol
      assert.equals 80, ftcp.spt
      assert.equals 12345, ftcp.dpt
      assert.equals 0, ftcp.seq_n
      assert.equals 1001, ftcp.ack_n
      assert.equals 0x14, ftcp.flags           -- RST + ACK
      assert.equals 0, ftcp.window
      assert.equals "", forged\sub ftcp.data_off
      -- Checksums : en-tête IPv4 et segment TCP (pseudo-header IPv4).
      assert.is_true ok_sum { forged\sub(1, 20) }
      seg = forged\sub 21
      pseudo = fip.src .. fip.dst .. "\0" .. string.char(6) .. sp(">H", #seg)
      assert.is_true ok_sum { pseudo, seg }

    it "IPv6 : swap L3/L4, checksum TCP sur pseudo-header IPv6", ->
      raw = ipv6_tcp 2000, 23456, 443
      ip, tcp = parse6 raw
      forged = wr.forge_tcp_rst ip, tcp
      fip, ftcp = parse6 forged
      assert.equals 6, fip.version
      assert.equals 20, fip.payload_len
      assert.equals DST6, require("ipparse.l3.ip").ip2s fip.src
      assert.equals SRC6, require("ipparse.l3.ip").ip2s fip.dst
      assert.equals 64, fip.hop_limit
      assert.equals 6, fip.next_header
      assert.equals 443, ftcp.spt
      assert.equals 23456, ftcp.dpt
      assert.equals 2001, ftcp.ack_n
      assert.equals 0x14, ftcp.flags
      seg = forged\sub fip.data_off
      assert.is_true ok_sum { pseudo6(fip.src, fip.dst, seg, 6), seg }

  describe "forge_icmp_reject", ->
    it "IPv4 : type 3 code 13, quote de l'original, checksum valide", ->
      raw = ipv4_udp "test-payload", 33434
      ip, _ = ip_mod.parse raw, 1
      forged = wr.forge_icmp_reject raw, ip
      fip, _ = ip_mod.parse forged, 1
      assert.equals 4, fip.version
      assert.equals 1, fip.protocol                     -- ICMP
      assert.equals DST4, require("ipparse.l3.ip").ip2s fip.src
      assert.equals SRC4, require("ipparse.l3.ip").ip2s fip.dst
      assert.equals 64, fip.ttl
      icmp = forged\sub fip.data_off
      assert.equals 3, icmp\byte(1)
      assert.equals 13, icmp\byte(2)
      assert.equals raw, icmp\sub(9)                    -- datagramme original cité
      assert.is_true ok_sum { icmp }
      assert.is_true ok_sum { forged\sub(1, 20) }

    it "IPv6 : type 1 code 1, checksum sur pseudo-header IPv6", ->
      raw = ipv6_udp "abc"
      ip, _ = ip_mod.parse raw, 1
      forged = wr.forge_icmp_reject raw, ip
      fip, _ = ip_mod.parse forged, 1
      assert.equals 6, fip.version
      assert.equals 58, fip.next_header                 -- ICMPv6
      assert.equals DST6, require("ipparse.l3.ip").ip2s fip.src
      assert.equals SRC6, require("ipparse.l3.ip").ip2s fip.dst
      icmp = forged\sub fip.data_off
      assert.equals 1, icmp\byte(1)
      assert.equals 1, icmp\byte(2)
      assert.equals raw, icmp\sub(9)
      assert.is_true ok_sum { pseudo6(fip.src, fip.dst, icmp, 58), icmp }

    it "borne le datagramme cité à 576 octets", ->
      raw = ipv4_udp string.rep("x", 700), 33434
      assert.equals 728, #raw
      ip, _ = ip_mod.parse raw, 1
      forged = wr.forge_icmp_reject raw, ip
      fip, _ = ip_mod.parse forged, 1
      icmp = forged\sub fip.data_off
      assert.equals 8 + 576, #icmp

  describe "handle_reject", ->
    invoke = ->
      wr.handle_reject nil, nil, 9

    it "TCP → verdict NF_ACCEPT avec un RST injecté", ->
      payload = ipv4_tcp 3000, 12345, 80
      rc = invoke!
      assert.equals -1, rc
      assert.equals 1, #verdicts
      assert.equals 9, verdicts[1].id
      assert.equals 1, verdicts[1].verdict              -- NF_ACCEPT
      fip, ftcp = parse4 verdicts[1].data
      assert.equals 0x14, ftcp.flags
      assert.equals 3001, ftcp.ack_n
      assert.equals DST4, require("ipparse.l3.ip").ip2s fip.src

    it "UDP → verdict NF_ACCEPT avec un ICMP admin-prohibited", ->
      payload = ipv4_udp "hello", 33434
      rc = invoke!
      assert.equals -1, rc
      assert.equals 1, #verdicts
      fip, _ = ip_mod.parse verdicts[1].data, 1
      assert.equals 1, fip.protocol
      icmp = verdicts[1].data\sub fip.data_off
      assert.equals 3, icmp\byte(1)
      assert.equals 13, icmp\byte(2)

    it "payload vide → NF_DROP sans payload de remplacement", ->
      payload = ""
      rc = invoke!
      assert.equals -1, rc
      assert.equals 1, #verdicts
      assert.equals 0, verdicts[1].verdict
      assert.is_nil verdicts[1].data

    it "paquet IP illisible → NF_DROP", ->
      payload = "\x45"
      rc = invoke!
      assert.equals -1, rc
      assert.equals 1, #verdicts
      assert.equals 0, verdicts[1].verdict
