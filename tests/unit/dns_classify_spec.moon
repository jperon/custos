-- tests/unit/dns_classify_spec.moon
-- Tests unitaires du module dns_classify (block / redirect / pass).

package.path = "src/?.lua;src/?/init.lua;src/?/?.lua;lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path

dns_mod = require "ipparse.l7.dns"
classify_mod = require "dns_classify"
{ :encode_dns_name } = require "lib.dns_name"
sp = require("ipparse.lib.pack_compat").pack

A     = dns_mod.types.A
AAAA  = dns_mod.types.AAAA
CNAME = dns_mod.types.CNAME
IN    = dns_mod.classes.IN

qname = "\7example\3com\0"
name_ptr = "\192\012"  -- pointeur de compression vers le qname (offset 12)

-- Construit un payload DNS de réponse brut et renvoie (raw, parsed).
build = (rcode, answers) ->
  ancount = #answers
  flags = 0x8000 + (rcode % 16)  -- QR=1 + rcode
  header = sp ">H H H H H H", 0x1234, flags, 1, ancount, 0, 0
  question = qname .. sp(">H H", A, IN)
  body = {}
  for a in *answers
    body[#body + 1] = (a.rname or name_ptr) .. sp(">H H I4 s2", a.rtype, IN, a.ttl or 60, a.rdata)
  raw = header .. question .. table.concat(body)
  raw, dns_mod.parse(raw, 1, false)

describe "dns_classify", ->
  describe "classify", ->
    it "NXDOMAIN → block", ->
      raw, dns = build dns_mod.rcodes.NXDOMAIN, {}
      assert.same "block", classify_mod.classify(dns, raw).verdict

    it "réponse A simple → pass", ->
      raw, dns = build dns_mod.rcodes.NOERROR, {
        { rtype: A, rdata: string.char(1, 2, 3, 4) }
      }
      assert.same "pass", classify_mod.classify(dns, raw).verdict

    it "réponse vide NOERROR → pass", ->
      raw, dns = build dns_mod.rcodes.NOERROR, {}
      assert.same "pass", classify_mod.classify(dns, raw).verdict

    it "CNAME → redirect avec cible et A/AAAA", ->
      raw, dns = build dns_mod.rcodes.NOERROR, {
        { rtype: CNAME, rdata: encode_dns_name("block.example.net"), ttl: 300 }
        { rname: encode_dns_name("block.example.net"), rtype: A, rdata: string.char(9, 9, 9, 9), ttl: 120 }
        { rname: encode_dns_name("block.example.net"), rtype: AAAA, rdata: string.rep("\0", 15) .. "\1", ttl: 90 }
      }
      res = classify_mod.classify dns, raw
      assert.same "redirect", res.verdict
      assert.same "block.example.net", res.cname_target
      assert.same 1, #res.a
      assert.same string.char(9, 9, 9, 9), res.a[1]
      assert.same 1, #res.aaaa
      assert.same 90, res.ttl  -- TTL minimal de la chaîne

    it "sinkhole A 0.0.0.0 → sinkhole (porte l'adresse nulle)", ->
      raw, dns = build dns_mod.rcodes.NOERROR, {
        { rtype: A, rdata: string.rep("\0", 4) }
      }
      res = classify_mod.classify dns, raw
      assert.same "sinkhole", res.verdict
      assert.same 1, #res.a
      assert.same string.rep("\0", 4), res.a[1]

    it "sinkhole AAAA :: → sinkhole", ->
      raw, dns = build dns_mod.rcodes.NOERROR, {
        { rtype: AAAA, rdata: string.rep("\0", 16) }
      }
      res = classify_mod.classify dns, raw
      assert.same "sinkhole", res.verdict
      assert.same 1, #res.aaaa

    it "sinkhole A 0.0.0.0 + AAAA :: → sinkhole", ->
      raw, dns = build dns_mod.rcodes.NOERROR, {
        { rtype: A, rdata: string.rep("\0", 4) }
        { rtype: AAAA, rdata: string.rep("\0", 16) }
      }
      assert.same "sinkhole", classify_mod.classify(dns, raw).verdict

    it "A non nulle parmi des nulles → pas un sinkhole (pass)", ->
      raw, dns = build dns_mod.rcodes.NOERROR, {
        { rtype: A, rdata: string.rep("\0", 4) }
        { rtype: A, rdata: string.char(1, 2, 3, 4) }
      }
      assert.same "pass", classify_mod.classify(dns, raw).verdict

    it "dns nil → pass", ->
      assert.same "pass", classify_mod.classify(nil, nil).verdict

  describe "numeric_rcode", ->
    it "renvoie la valeur numérique (pas un booléen)", ->
      _, dns = build dns_mod.rcodes.NXDOMAIN, {}
      assert.same dns_mod.rcodes.NXDOMAIN, classify_mod.numeric_rcode(dns.header)

  describe "has_cname_target", ->
    it "vrai si le même CNAME est présent (insensible à la casse)", ->
      raw, dns = build dns_mod.rcodes.NOERROR, {
        { rtype: CNAME, rdata: encode_dns_name "Forcesafesearch.Google.com" }
      }
      assert.is_true classify_mod.has_cname_target(dns, raw, "forcesafesearch.google.com")

    it "faux si CNAME différent", ->
      raw, dns = build dns_mod.rcodes.NOERROR, {
        { rtype: CNAME, rdata: encode_dns_name "autre.example.net" }
      }
      assert.is_false classify_mod.has_cname_target(dns, raw, "forcesafesearch.google.com")

    it "faux si pas de CNAME", ->
      raw, dns = build dns_mod.rcodes.NOERROR, {
        { rtype: A, rdata: string.char(1, 2, 3, 4) }
      }
      assert.is_false classify_mod.has_cname_target(dns, raw, "x.example.net")
