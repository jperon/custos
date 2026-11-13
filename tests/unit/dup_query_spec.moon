-- tests/unit/dup_query_spec.moon
-- Tests unitaires de dup_query (sélection famille + duplication UDP).

package.path = "src/?.lua;src/?/init.lua;src/?/?.lua;lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path

dup = require "dup_query"
{ parse: parse_ip, new: new_ip, :s2ip, :ip2s } = require "ipparse.l3.ip"
{ parse: parse_udp, new: new_udp } = require "ipparse.l4.udp"
sp = require("ipparse.lib.pack_compat").pack
bit = require "bit"

-- Construit un paquet IPv4/UDP/DNS minimal (octets bruts).
build_v4 = (src, dst, dns) ->
  udp_len = 8 + #dns
  total = 20 + udp_len
  ihl = sp ">B B H H H B B H", 0x45, 0, total, 0x1234, 0, 64, 17, 0
  ihl ..= s2ip(src) .. s2ip(dst)
  udp = sp(">H H H H", 5353, 53, udp_len, 0) .. dns
  ihl .. udp

-- Construit un paquet IPv6/UDP/DNS minimal (octets bruts), TC et flow label
-- non nuls pour vérifier que la recopie ne les perd pas.
build_v6 = (src, dst, dns, tc=0, fl=0) ->
  udp_len = 8 + #dns
  vtf = bit.bor bit.lshift(6, 28), bit.lshift(tc, 20), fl
  hdr = sp ">I4 I2 B B", vtf, udp_len, 17, 64
  hdr .. s2ip(src) .. s2ip(dst) .. sp(">H H H H", 5353, 53, udp_len, 0) .. dns

-- Paquet attendu construit indépendamment du module testé (reconstruction
-- ipparse + sérialisation), pour comparer les octets de la recopie à une
-- référence qui ne partage pas son code.
expected_packet = (ip, l4, dns, validator) ->
  udp = new_udp { spt: l4.spt, dpt: l4.dpt, checksum: 0, data: dns }
  pkt = new_ip {
    version:  ip.version
    v_ihl:    ip.v_ihl
    tos:      ip.tos
    id:       ip.id
    ff:       ip.ff
    ttl:      ip.ttl
    options:  ip.options or ""
    traffic_class: ip.traffic_class
    flow_label:    ip.flow_label
    hop_limit:     ip.hop_limit
    src:      ip.src
    dst:      s2ip(validator)
    protocol: 17
    next_header: 17
    data:     udp
  }
  "#{pkt}"

describe "dup_query", ->
  describe "pick_resolver", ->
    resolvers = { "2a01:4f8::1", "94.130.180.225", "78.47.64.161" }
    it "choisit une IPv4 pour un paquet v4", ->
      assert.same "94.130.180.225", dup.pick_resolver(resolvers, 4)
    it "choisit une IPv6 pour un paquet v6", ->
      assert.same "2a01:4f8::1", dup.pick_resolver(resolvers, 6)
    it "nil si aucune IP de la bonne famille", ->
      assert.is_nil dup.pick_resolver({ "1.2.3.4" }, 6)
    it "ignore une URL DoH (elle contient ':' mais n'est pas une IPv6)", ->
      assert.same "2a01:4f8::1", dup.pick_resolver({ "https://dns.example/dns-query", "2a01:4f8::1" }, 6)
    it "nil sur liste vide", ->
      assert.is_nil dup.pick_resolver({}, 4)

  describe "new_picker", ->
    v4 = { "94.130.180.225", "78.47.64.161", "167.235.236.107" }
    mixed = { "https://dns.example/dns-query", "94.0.0.1", "78.0.0.1", "2a01::1", "2a01::2" }

    it "répartit sur les n adresses IPv4 ((id + port) % n)", ->
      pick = dup.new_picker v4
      seen = {}
      for i = 0, 2
        ip = pick 4, i, 1000
        assert.is_truthy ip
        seen[ip] = true
      for ip in *v4
        assert.is_true seen[ip] == true

    it "respecte la famille du paquet", ->
      pick = dup.new_picker mixed
      for i = 0, 9
        ip4 = pick 4, i, 53
        ip6 = pick 6, i, 53
        assert.is_nil (ip4\find ":", 1, true)
        assert.is_not_nil (ip6\find ":", 1, true)

    it "ignore les URL https:// (jamais choisies)", ->
      pick = dup.new_picker mixed
      for i = 0, 20
        for ver in *{ 4, 6 }
          ip = pick ver, i, 4242
          assert.is_nil (ip\find "://", 1, true)

    it "est déterministe pour un même (id, port)", ->
      pick = dup.new_picker v4
      assert.same pick(4, 0x1234, 5353), pick(4, 0x1234, 5353)

    it "liste à une seule adresse : renvoie toujours celle-ci", ->
      pick = dup.new_picker { "94.0.0.1" }
      for i = 0, 5
        assert.same "94.0.0.1", pick 4, i, i

    it "liste vide → nil", ->
      pick = dup.new_picker {}
      assert.is_nil pick 4, 1, 1
      assert.is_nil pick 6, 1, 1

    it "aucune IP de la famille demandée → nil", ->
      pick = dup.new_picker { "94.0.0.1" }
      assert.is_nil pick 6, 1, 1

    it "get_picker mémoïse le sélecteur par liste", ->
      assert.is_true dup.get_picker(v4) == dup.get_picker(v4)

    it "get_picker accepte une liste nil (aucun validateur)", ->
      pick = dup.get_picker nil
      assert.is_nil pick 4, 1, 1

  describe "build_udp", ->
    dns = "\xab\xcd\1\0\0\1\0\0\0\0\0\0\7example\3com\0\0\1\0\1"

    it "réécrit la dst et préserve src + payload DNS", ->
      raw = build_v4 "192.0.2.10", "1.1.1.1", dns
      ip, _ = parse_ip raw, 1
      l4, _ = parse_udp raw, ip.data_off
      l4.proto = "udp"
      out = dup.build_udp ip, l4, dns, "94.130.180.225", raw
      assert.is_truthy out
      oip, _ = parse_ip out, 1
      assert.same "192.0.2.10", ip2s(oip.src)
      assert.same "94.130.180.225", ip2s(oip.dst)
      oudp, _ = parse_udp out, oip.data_off
      payload = out\sub oudp.data_off, oudp.off + oudp.len - 1
      assert.same dns, payload
      assert.is_true expected_packet(ip, l4, dns, "94.130.180.225") == out

    it "nil en TCP", ->
      raw = build_v4 "192.0.2.10", "1.1.1.1", dns
      ip, _ = parse_ip raw, 1
      l4, _ = parse_udp raw, ip.data_off
      l4.proto = "tcp"
      assert.is_nil dup.build_udp ip, l4, dns, "94.130.180.225", raw

    it "nil si famille validateur incohérente", ->
      raw = build_v4 "192.0.2.10", "1.1.1.1", dns
      ip, _ = parse_ip raw, 1
      l4, _ = parse_udp raw, ip.data_off
      l4.proto = "udp"
      assert.is_nil dup.build_udp ip, l4, dns, "2a01:4f8::1", raw

    it "nil sans paquet d'origine (raw obligatoire)", ->
      raw = build_v4 "192.0.2.10", "1.1.1.1", dns
      ip, _ = parse_ip raw, 1
      l4, _ = parse_udp raw, ip.data_off
      l4.proto = "udp"
      assert.is_nil dup.build_udp ip, l4, dns, "94.130.180.225"

    it "préserve traffic_class/flow_label IPv6 (vtf recalculé par ip6.pack)", ->
      raw = build_v6 "2001:db8::10", "2001:db8::53", dns, 0x2e, 0x12345
      ip, _ = parse_ip raw, 1
      l4, _ = parse_udp raw, ip.data_off
      l4.proto = "udp"
      out = dup.build_udp ip, l4, dns, "2a01:4f8::1", raw
      assert.is_truthy out
      oip, _ = parse_ip out, 1
      assert.equals 0x2e, oip.traffic_class
      assert.equals 0x12345, oip.flow_label

    -- Sortie comparée à un paquet attendu construit hors du module (helper
    -- expected_packet) : une erreur de recopie ou de checksum est détectée.
    it "IPv4 : octets identiques au paquet attendu construit indépendamment", ->
      raw = build_v4 "192.0.2.10", "1.1.1.1", dns
      ip, _ = parse_ip raw, 1
      l4, _ = parse_udp raw, ip.data_off
      l4.proto = "udp"
      expected = expected_packet ip, l4, dns, "94.130.180.225"
      out = dup.build_udp ip, l4, dns, "94.130.180.225", raw
      assert.same #expected, #out
      assert.is_true expected == out

    it "IPv6 : octets identiques au paquet attendu construit indépendamment", ->
      raw = build_v6 "2001:db8::10", "2001:db8::53", dns, 0x2e, 0x12345
      ip, _ = parse_ip raw, 1
      l4, _ = parse_udp raw, ip.data_off
      l4.proto = "udp"
      expected = expected_packet ip, l4, dns, "2a01:4f8::1"
      out = dup.build_udp ip, l4, dns, "2a01:4f8::1", raw
      assert.same #expected, #out
      assert.is_true expected == out

    it "ignore le bourrage au-delà du datagramme IP", ->
      raw = build_v4 "192.0.2.10", "1.1.1.1", dns
      ip, _ = parse_ip raw, 1
      l4, _ = parse_udp raw, ip.data_off
      l4.proto = "udp"
      padded = raw .. "\0\0\0\0\0\0\0\0"
      out = dup.build_udp ip, l4, dns, "94.130.180.225", padded
      expected = expected_packet ip, l4, dns, "94.130.180.225"
      assert.same #raw, #out
      assert.is_true expected == out

    it "nil en TCP et sur famille incohérente (raw fourni)", ->
      raw = build_v4 "192.0.2.10", "1.1.1.1", dns
      ip, _ = parse_ip raw, 1
      l4, _ = parse_udp raw, ip.data_off
      l4.proto = "tcp"
      assert.is_nil dup.build_udp ip, l4, dns, "94.130.180.225", raw
      l4.proto = "udp"
      assert.is_nil dup.build_udp ip, l4, dns, "2a01:4f8::1", raw

    it "mémoïse la conversion de l'IP validateur", ->
      raw = build_v4 "192.0.2.10", "1.1.1.1", dns
      ip, _ = parse_ip raw, 1
      l4, _ = parse_udp raw, ip.data_off
      l4.proto = "udp"
      first = dup.dst_raw_of "94.130.180.225"
      assert.same 4, #first
      assert.is_true first == dup.dst_raw_of("94.130.180.225")
      assert.is_nil dup.dst_raw_of "pas-une-ip"
      assert.is_nil dup.dst_raw_of nil

  describe "build_query", ->
    query = "\xab\xcd\1\0\0\1\0\0\0\0\0\0\7example\3com\0\0\1\0\1"

    it "inverse src/dst et ports à partir des en-têtes de la réponse", ->
      -- Réponse résolveur→client : src=1.1.1.1:53, dst=192.0.2.10:5353.
      raw = build_v4 "1.1.1.1", "192.0.2.10", query
      ip, _ = parse_ip raw, 1
      l4, _ = parse_udp raw, ip.data_off
      l4.proto = "udp"
      out = dup.build_query ip, l4, query
      assert.is_truthy out
      oip, _ = parse_ip out, 1
      assert.same "192.0.2.10", ip2s(oip.src)   -- client (spoofé)
      assert.same "1.1.1.1", ip2s(oip.dst)       -- résolveur
      oudp, _ = parse_udp out, oip.data_off
      -- Ports inversés : la requête part du port client (= dpt de la réponse)
      -- vers le résolveur (= spt de la réponse). Le helper fixe spt=5353/dpt=53.
      assert.same 53, oudp.spt
      assert.same 5353, oudp.dpt
      payload = out\sub oudp.data_off, oudp.off + oudp.len - 1
      assert.same query, payload

    it "préserve traffic_class/flow_label IPv6 (vtf recalculé par ip6.pack)", ->
      ip6 = new_ip { version: 6, src: s2ip("2001:db8::53"), dst: s2ip("2001:db8::10"), next_header: 17, hop_limit: 64, data: "" }
      ip6.traffic_class = 0x2e
      ip6.flow_label = 0x12345
      l4 = { proto: "udp", spt: 53, dpt: 5353 }
      out = dup.build_query ip6, l4, query
      assert.is_truthy out
      oip, _ = parse_ip out, 1
      assert.equals 0x2e, oip.traffic_class
      assert.equals 0x12345, oip.flow_label

    it "nil en TCP", ->
      raw = build_v4 "1.1.1.1", "192.0.2.10", query
      ip, _ = parse_ip raw, 1
      l4, _ = parse_udp raw, ip.data_off
      l4.proto = "tcp"
      assert.is_nil dup.build_query ip, l4, query

    it "nil sans payload", ->
      raw = build_v4 "1.1.1.1", "192.0.2.10", query
      ip, _ = parse_ip raw, 1
      l4, _ = parse_udp raw, ip.data_off
      l4.proto = "udp"
      assert.is_nil dup.build_query ip, l4, nil
