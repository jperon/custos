-- tests/unit/lib/dns_response_spec.moon
ffi = require "ffi"
bit = require "bit"
D   = require "lib.dns_response"

describe "lib.dns_response", ->
  describe "replace_dns_payload (UDP/IPv4)", ->
    it "reconstruit un paquet avec le nouveau payload et un checksum valide", ->
      -- En-tête IPv4 (20) + UDP (8) + ancien payload (4 octets).
      raw = string.rep "\0", 32
      raw = string.char(0x45) .. raw\sub 2   -- version 4, IHL 5
      ip  = { version: 4 }
      l4  = { proto: "udp" }
      new_dns = "abcdef"
      out = D.replace_dns_payload raw, ip, l4, 20, new_dns
      assert.is_string out
      -- 20 (IP) + 8 (UDP) + 6 (payload)
      assert.equals 34, #out
      -- Le payload DNS est bien recopié en fin de paquet.
      assert.equals new_dns, out\sub 29, 34
      -- Le checksum UDP (pseudo-header inclus) se replie à 0xFFFF.
      p = ffi.cast "const uint8_t*", out
      r16 = (o) -> bit.bor bit.lshift(p[o], 8), p[o + 1]
      sum = 0
      for i = 12, 18, 2
        sum += r16 i
      sum += 17 + (#out - 20)
      i = 20
      while i < #out
        sum += r16 i
        i += 2
      while bit.rshift(sum, 16) != 0
        sum = bit.band(sum, 0xFFFF) + bit.rshift(sum, 16)
      assert.equals 0xFFFF, sum

    it "renvoie nil pour un protocole non géré", ->
      assert.is_nil D.replace_dns_payload (string.rep "\0", 40), { version: 4 }, { proto: "icmp" }, 20, "x"

  describe "decode_simple_cname", ->
    it "décode une suite de labels", ->
      rdata = "\3foo\7example\3com\0"
      assert.equals "foo.example.com", D.decode_simple_cname rdata

    it "renvoie (cname) sur un pointeur de compression", ->
      rdata = string.char(0xC0, 0x0C)
      assert.equals "(cname)", D.decode_simple_cname rdata

  describe "build_query_from_response", ->
    -- Réponse : en-tête (QR=1,RD=1 ; RA=1,RCODE=2 SERVFAIL ; qd=1,an=1) +
    -- question www.example.com/A/IN + un answer factice.
    question = "\3www\7example\3com\0" .. string.char(0, 1, 0, 1)
    header   = string.char(0x12, 0x34, 0x81, 0x82, 0, 1, 0, 1, 0, 0, 0, 0)
    answer   = string.char(0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4)
    response = header .. question .. answer

    it "ne garde que l'en-tête et la section question", ->
      q = D.build_query_from_response response, 1
      assert.is_string q
      assert.equals 12 + #question, #q
      assert.equals question, q\sub 13

    it "normalise les drapeaux (QR=0, RD=1) et remet les compteurs AN/NS/AR à 0", ->
      q = D.build_query_from_response response, 1
      assert.equals 0x12, q\byte 1          -- ID conservé
      assert.equals 0x34, q\byte 2
      assert.equals 0x01, q\byte 3          -- QR effacé, RD positionné
      assert.equals 0x00, q\byte 4          -- RA/Z/RCODE remis à 0
      assert.equals 1, q\byte 6             -- QDCOUNT conservé
      assert.equals 0, q\byte 8             -- ANCOUNT = 0
      assert.equals 0, q\byte 10            -- NSCOUNT = 0
      assert.equals 0, q\byte 12            -- ARCOUNT = 0

    it "qdcount par défaut à 1", ->
      q = D.build_query_from_response response
      assert.is_string q
      assert.equals 12 + #question, #q

    it "renvoie nil sur un payload trop court", ->
      assert.is_nil D.build_query_from_response "\0\0\0", 1

    it "renvoie nil si qdcount < 1", ->
      assert.is_nil D.build_query_from_response response, 0

    it "renvoie nil sur une question tronquée", ->
      truncated = header .. "\7example"   -- label sans terminateur ni qtype/qclass
      assert.is_nil D.build_query_from_response truncated, 1

    it "rejette un pointeur de compression dans la question", ->
      bad = header .. string.char(0xC0, 0x0C, 0, 1, 0, 1)
      assert.is_nil D.build_query_from_response bad, 1

  describe "fmt_rdata", ->
    it "formate un enregistrement A", ->
      assert.equals "1.2.3.4", D.fmt_rdata { rtype: 1, rdata: string.char(1, 2, 3, 4) }

    it "formate un CNAME", ->
      assert.equals "host.lan", D.fmt_rdata { rtype: 5, rdata: "\4host\3lan\0" }

    it "résume un type inconnu", ->
      assert.equals "(rdata 3B)", D.fmt_rdata { rtype: 99, rdata: "xyz" }
