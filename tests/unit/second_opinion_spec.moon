-- tests/unit/second_opinion_spec.moon
-- Tests unitaires de l'état « second avis » (verdicts, park, expiration).

package.path = "src/?.lua;src/?/init.lua;src/?/?.lua;lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path

so_mod = require "second_opinion"

describe "second_opinion", ->
  describe "is_validator", ->
    it "reconnaît les IP de la liste resolvers", ->
      so = so_mod.new resolvers: { "94.130.180.225", "2a01:4f8::1" }
      assert.is_true so.is_validator "94.130.180.225"
      assert.is_true so.is_validator "2a01:4f8::1"
      assert.is_false so.is_validator "1.1.1.1"

  describe "active_for", ->
    it "respecte les familles configurées", ->
      so = so_mod.new families: { ipv4: true, ipv6: false }
      assert.is_true so.active_for 4
      assert.is_false so.active_for 6
    it "actif par défaut pour les deux familles", ->
      so = so_mod.new!
      assert.is_true so.active_for 4
      assert.is_true so.active_for 6

  describe "corr_key", ->
    it "est identique pour A et B (insensible casse qname)", ->
      so = so_mod.new!
      a = so.corr_key "192.0.2.1", 0x1234, "Example.COM"
      b = so.corr_key "192.0.2.1", 0x1234, "example.com"
      assert.same a, b

  describe "verdicts", ->
    it "store puis take consomme le verdict", ->
      so = so_mod.new verdict_ttl_s: 5
      so.store_verdict "k", { verdict: "block" }, 100
      got = so.take_verdict "k", 101
      assert.same "block", got.verdict
      assert.is_nil so.take_verdict "k", 102   -- consommé

    it "take renvoie nil si expiré", ->
      so = so_mod.new verdict_ttl_s: 5
      so.store_verdict "k", { verdict: "pass" }, 100
      assert.is_nil so.take_verdict "k", 200

    -- Sans purge_verdicts, un verdict B jamais consommé par take_verdict (A
    -- jamais arrivé : paquet perdu, client qui abandonne) reste en mémoire
    -- indéfiniment (fuite non bornée).
    it "purge_verdicts supprime un verdict expiré jamais consommé", ->
      so = so_mod.new verdict_ttl_s: 5
      so.store_verdict "k", { verdict: "block" }, 100
      so.purge_verdicts 200
      -- Après purge, même à t=101 (dans la fenêtre TTL d'origine), le
      -- verdict a bien disparu — la purge n'attend pas une lecture.
      assert.is_nil so.take_verdict "k", 101

    it "purge_verdicts conserve un verdict non expiré", ->
      so = so_mod.new verdict_ttl_s: 5
      so.store_verdict "k", { verdict: "block" }, 100
      so.purge_verdicts 101
      got = so.take_verdict "k", 102
      assert.same "block", got.verdict

  describe "encode_verdict / decode_verdict (bus inter-workers)", ->
    it "round-trip block", ->
      line = so_mod.encode_verdict "192.0.2.10", 0x1a2b, "Example.COM", { kind: "block" }
      assert.is_string line
      rec, err = so_mod.decode_verdict line
      assert.is_nil err
      assert.equals "192.0.2.10", rec.client_ip
      assert.equals 0x1a2b, rec.txid
      assert.equals "Example.COM", rec.qname
      assert.equals "block", rec.override.kind

    it "round-trip sinkhole : adresses et ttl préservés", ->
      line = so_mod.encode_verdict "192.0.2.10", 1, "a.test", {
        kind: "sinkhole", a: { "\0\0\0\0" }, aaaa: { }, ttl: 42
      }
      rec = so_mod.decode_verdict line
      assert.equals "sinkhole", rec.override.kind
      assert.same { "\0\0\0\0" }, rec.override.a
      assert.equals 42, rec.override.ttl

    it "round-trip redirect : cible CNAME et AAAA", ->
      aaaa = "\32\1\13\184\0\0\0\0\0\0\0\0\0\0\0\1"
      line = so_mod.encode_verdict "2001:db8::10", 0xffff, "b.test", {
        kind: "redirect", cname_target: "forcesafesearch.google.com", a: {}, aaaa: { aaaa }, ttl: 60
      }
      rec = so_mod.decode_verdict line
      assert.equals "redirect", rec.override.kind
      assert.equals "forcesafesearch.google.com", rec.override.cname_target
      assert.same { aaaa }, rec.override.aaaa

    it "round-trip pass (pas d'adresse)", ->
      rec = so_mod.decode_verdict so_mod.encode_verdict "192.0.2.1", 2, "c.test", { kind: "pass" }
      assert.equals "pass", rec.override.kind
      assert.same {}, rec.override.a

    it "refuse un kind inconnu, un txid hors bornes ou une ligne tronquée", ->
      assert.is_nil so_mod.encode_verdict "192.0.2.1", 1, "x", { kind: "bogus" }
      assert.is_nil so_mod.decode_verdict "v1|zzzz|192.0.2.1|0001|0||||"
      assert.is_nil so_mod.decode_verdict "v1|b|192.0.2.1"
      assert.is_nil so_mod.decode_verdict "v1|b|192.0.2.1|10000|0||||"   -- txid > 65535
      assert.is_nil so_mod.decode_verdict "v1|b|192.0.2.1|0001|0||zz||"  -- hex invalide

  describe "park / take_parked", ->
    it "parque puis récupère le ctx", ->
      so = so_mod.new!
      so.park "k", { pkt: 1 }, 1000
      assert.same { pkt: 1 }, so.take_parked "k"
      assert.is_nil so.take_parked "k"

  describe "expired", ->
    it "renvoie les ctx dont le budget est dépassé", ->
      so = so_mod.new budget_ms: 80
      so.park "k1", { id: 1 }, 1000   -- deadline 1080
      so.park "k2", { id: 2 }, 1000
      assert.same {}, so.expired 1050         -- aucun dépassé
      exp = so.expired 1080
      assert.same 2, #exp
      assert.is_false so.has_parked!           -- tous retirés
