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
