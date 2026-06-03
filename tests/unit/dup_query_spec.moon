-- tests/unit/dup_query_spec.moon
-- Tests unitaires de dup_query (sélection famille + duplication UDP).

package.path = "src/?.lua;src/?/init.lua;src/?/?.lua;lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path

dup = require "dup_query"
{ parse: parse_ip, :s2ip, :ip2s } = require "ipparse.l3.ip"
{ parse: parse_udp } = require "ipparse.l4.udp"
sp = require("ipparse.lib.pack_compat").pack

-- Construit un paquet IPv4/UDP/DNS minimal (octets bruts).
build_v4 = (src, dst, dns) ->
  udp_len = 8 + #dns
  total = 20 + udp_len
  ihl = sp ">B B H H H B B H", 0x45, 0, total, 0x1234, 0, 64, 17, 0
  ihl ..= s2ip(src) .. s2ip(dst)
  udp = sp(">H H H H", 5353, 53, udp_len, 0) .. dns
  ihl .. udp

describe "dup_query", ->
  describe "pick_resolver", ->
    resolvers = { "2a01:4f8::1", "94.130.180.225", "78.47.64.161" }
    it "choisit une IPv4 pour un paquet v4", ->
      assert.same "94.130.180.225", dup.pick_resolver(resolvers, 4)
    it "choisit une IPv6 pour un paquet v6", ->
      assert.same "2a01:4f8::1", dup.pick_resolver(resolvers, 6)
    it "nil si aucune IP de la bonne famille", ->
      assert.is_nil dup.pick_resolver({ "1.2.3.4" }, 6)

  describe "build_udp", ->
    dns = "\xab\xcd\1\0\0\1\0\0\0\0\0\0\7example\3com\0\0\1\0\1"

    it "réécrit la dst et préserve src + payload DNS", ->
      raw = build_v4 "192.0.2.10", "1.1.1.1", dns
      ip, _ = parse_ip raw
      l4, _ = parse_udp raw, ip.data_off
      l4.proto = "udp"
      out = dup.build_udp ip, l4, dns, "94.130.180.225"
      assert.is_truthy out
      oip, _ = parse_ip out
      assert.same "192.0.2.10", ip2s(oip.src)
      assert.same "94.130.180.225", ip2s(oip.dst)
      oudp, _ = parse_udp out, oip.data_off
      payload = out\sub oudp.data_off, oudp.off + oudp.len - 1
      assert.same dns, payload

    it "nil en TCP", ->
      raw = build_v4 "192.0.2.10", "1.1.1.1", dns
      ip, _ = parse_ip raw
      l4, _ = parse_udp raw, ip.data_off
      l4.proto = "tcp"
      assert.is_nil dup.build_udp ip, l4, dns, "94.130.180.225"

    it "nil si famille validateur incohérente", ->
      raw = build_v4 "192.0.2.10", "1.1.1.1", dns
      ip, _ = parse_ip raw
      l4, _ = parse_udp raw, ip.data_off
      l4.proto = "udp"
      assert.is_nil dup.build_udp ip, l4, dns, "2a01:4f8::1"
