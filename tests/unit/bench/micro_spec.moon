-- tests/unit/bench/micro_spec.moon
-- Tests du volet micro-bench in-process.

micro = require "bench.micro"
{ :bench, :run } = micro

describe "bench/micro", ->

  describe "bench", ->
    it "mesure ns/op et KB alloués d'une fonction", ->
      called = 0
      r = bench "noop", 1000, (n) ->
        for i = 1, n
          called += 1
      assert.equal "noop", r.name
      assert.equal 1000, called
      assert.is_number r.ns_per_op
      assert.is_true r.ns_per_op >= 0
      assert.is_number r.kb_alloc

  describe "run", ->
    it "renvoie une liste de cas, chacun {name, ns_per_op, kb_alloc}", ->
      cases = run { iters: 100 }
      assert.is_true #cases > 0
      for c in *cases
        assert.is_string c.name
        assert.is_number c.ns_per_op

    it "un cas dont le setup échoue est marqué skipped au lieu de planter", ->
      cases = run {
        iters: 10
        extra_cases: {
          { name: "casse", setup: -> error "boom" }
        }
      }
      casse = nil
      for c in *cases
        casse = c if c.name == "casse"
      assert.is_truthy casse
      assert.is_true casse.skipped
