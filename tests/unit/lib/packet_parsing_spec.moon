-- tests/unit/lib/packet_parsing_spec.moon
-- Tests unitaires de l'agrégateur lib.packet_parsing : ré-exports ipparse
-- identiques, sauf `ip2s` (mémoïsation IPv4, cf. docs/agents/perf.md §26).

package.path = "lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path

pp = require "lib.packet_parsing"
ipparse = require "ipparse.l3.ip"

describe "lib.packet_parsing", ->
  describe "ré-exports", ->
    it "expose les primitives de parsing d'ipparse", ->
      for name in *{ "parse_ip4", "parse_ip6", "parse_udp", "parse_tcp", "parse_dns" }
        assert.is_function pp[name], name
      assert.is_table pp.dns_types

  describe "ip2s", ->
    it "convertit une IPv4 (4 octets) comme ipparse", ->
      raw = "\192\168\1\42"
      assert.same "192.168.1.42", pp.ip2s raw
      assert.same ipparse.ip2s(raw), pp.ip2s(raw)

    it "convertit une IPv6 (16 octets) comme ipparse", ->
      raw = "\32\1\13\184\0\0\0\0\0\0\0\0\0\0\0\1"
      assert.same ipparse.ip2s(raw), pp.ip2s(raw)
      assert.is_truthy pp.ip2s(raw)\find ":", 1, true

    it "rend la MÊME valeur sur un hit de cache", ->
      raw = "\10\35\1\2"
      first = pp.ip2s raw
      assert.same "10.35.1.2", first
      -- 3 appels supplémentaires : même valeur (identité de chaîne, le cache
      -- rend l'objet déjà interné).
      for _ = 1, 3
        assert.is_true first == pp.ip2s(raw)

    it "distingue les adresses (pas de collision entre clés)", ->
      a = pp.ip2s "\10\35\1\2"
      b = pp.ip2s "\10\35\1\3"
      assert.same "10.35.1.2", a
      assert.same "10.35.1.3", b
      assert.is_true a != b

    it "nil sur entrée nil (aucun appelant ne passe nil : durcissement)", ->
      assert.is_nil pp.ip2s nil

    it "borne son cache (purge en bloc, pas de croissance non bornée)", ->
      -- 600 adresses distinctes (> IP2S_CACHE_MAX) : aucune erreur, et les
      -- conversions restent correctes après la purge.
      for i = 1, 600
        raw = "\10\0" .. string.char(math.floor(i / 256), i % 256)
        assert.is_truthy pp.ip2s raw
      assert.same "10.35.1.1", pp.ip2s "\10\35\1\1"
