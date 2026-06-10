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

  describe "fmt_rdata", ->
    it "formate un enregistrement A", ->
      assert.equals "1.2.3.4", D.fmt_rdata { rtype: 1, rdata: string.char(1, 2, 3, 4) }

    it "formate un CNAME", ->
      assert.equals "host.lan", D.fmt_rdata { rtype: 5, rdata: "\4host\3lan\0" }

    it "résume un type inconnu", ->
      assert.equals "(rdata 3B)", D.fmt_rdata { rtype: 99, rdata: "xyz" }
