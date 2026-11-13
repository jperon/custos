-- tests/unit/bench/hotpath_spec.moon
-- Tests unitaires du micro-banc hot path (paquets fabriqués, mesures par étape)
-- et des sondes par étape (bench/stage_probe).

package.path = "src/?.lua;src/?/init.lua;src/?/?.lua;lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path

hp = require "bench.hotpath"
stage_probe = require "bench.stage_probe"

describe "bench.hotpath", ->
  describe "fabrication de paquets", ->
    it "encode un nom en labels + nul", ->
      assert.same "\3www\7example\3com\0", hp.encode_name "www.example.com"

    it "construit une requête DNS (QR=0, RD, qdcount=1)", ->
      q = hp.build_query "example.com", 0x1234
      assert.same 0x12, q\byte(1)
      assert.same 0x34, q\byte(2)
      assert.same 0x01, q\byte(3)   -- RD
      assert.same 0x00, q\byte(4)   -- QR=0
      assert.same 1, q\byte(6)      -- qdcount
      assert.is_truthy q\find "example", 1, true

    it "construit une réponse avec N enregistrements A", ->
      resp = hp.build_answer "example.com", 0x1234, { "100.64.0.1", "100.64.0.2" }
      assert.same 0x81, resp\byte(3)      -- QR=1 (octet haut du champ flags)
      assert.same 2, resp\byte(8)         -- ancount (octet bas)
      assert.is_truthy resp\find "\100\64\0\1", 1, true
      assert.is_truthy resp\find "\100\64\0\2", 1, true

    it "enveloppe dans IPv4/UDP avec les bonnes longueurs", ->
      pkt = hp.ipv4_udp "10.0.0.1", "10.0.0.2", 1234, 53, "abcd"
      assert.same 32, #pkt          -- 20 (IP) + 8 (UDP) + 4 (charge)
      assert.same 0x45, pkt\byte(1) -- version 4, IHL 5
      assert.same 32, pkt\byte(3) * 256 + pkt\byte(4)   -- total length
      assert.same 12, pkt\byte(25) * 256 + pkt\byte(26) -- longueur UDP

    it "le paquet question porte le port client et le port 53", ->
      pkt = hp.build_question_packet "example.com"
      assert.same 5353, pkt\byte(21) * 256 + pkt\byte(22)
      assert.same 53, pkt\byte(23) * 256 + pkt\byte(24)

    it "le paquet réponse porte les 8 adresses du profil", ->
      pkt = hp.build_response_packet "10.35.1.1", "example.com", { "1.1.1.1" }
      assert.is_truthy pkt\find "\1\1\1\1", 1, true

  describe "formatage du rapport", ->
    it "top_n trie décroissant et borne", ->
      top = hp.top_n { a: 2, b: 9, c: 5 }, 2
      assert.same 2, #top
      assert.same "b", top[1].key
      assert.same "c", top[2].key

    it "format_pct formate une décimale et gère le total nul", ->
      assert.same "50.0", hp.format_pct 1, 2
      assert.same "0.0", hp.format_pct 0, 0

  describe "mesure par étape", ->
    it "step_names prend les labels déclarés ou stepN par défaut", ->
      c = { steps: { (-> 1), (-> 2) }, labels: { "premier" } }
      names = hp.step_names c
      assert.same 2, #names
      assert.same "premier", names[1]
      assert.same "step2", names[2]

    it "measure_steps chronomètre chaque étape et prépare chaque itération", ->
      calls = { pre: 0, s1: 0, s2: 0 }
      c = {
        labels: { "s1", "s2" }
        pre: -> calls.pre += 1
        steps: {
          -> calls.s1 += 1
          -> calls.s2 += 1
        }
      }
      res = hp.measure_steps c, 100, 10, 1
      assert.same 2, #res
      assert.same "s1", res[1].name
      assert.same 100, calls.pre
      assert.same 100, calls.s1
      assert.same 100, calls.s2
      for e in *res
        assert.is_true e.us >= 0

    it "measure_steps_alloc attribue les octets à la bonne étape", ->
      -- Une étape qui alloue (concaténation de 4 Ko, valeur UNIQUE par
      -- itération : sinon LuaJIT interne la chaîne et la mesure tombe à 0,
      -- cf. docs/agents/perf.md §22.1) et une étape qui n'alloue rien.
      big = string.rep "x", 4096
      sink = {}
      counter = { n: 0 }
      c = {
        labels: { "alloue", "inerte" }
        steps: {
          ->
            counter.n += 1
            sink[1] = big .. counter.n
            1
          -> 1
        }
      }
      res = hp.measure_steps_alloc c, 20, 20
      assert.same 2, #res
      assert.is_true res[1].bytes > 3000
      assert.is_true res[2].bytes < 100

    it "run_probed exécute le cas et rend les sondes triées", ->
      p = stage_probe.new!
      mod = { f: (x) -> x + 1 }
      assert.is_true p.wrap mod, "f", "mod.f"
      c = { steps: { -> mod.f 1 } }
      res = hp.run_probed c, 50, 10, p
      assert.same 1, #res
      assert.same "mod.f", res[1].label
      assert.same 50, res[1].calls
      assert.is_true res[1].us >= 0

describe "bench.stage_probe", ->
  it "enveloppe une fonction sans changer sa valeur de retour", ->
    p = stage_probe.new!
    mod = { f: (a, b) -> a + b }
    p.wrap mod, "f", "f"
    assert.same 5, mod.f 2, 3
    res = p.results 1
    assert.same 1, res[1].calls
    assert.same 1, res[1].calls_req

  it "préserve plusieurs valeurs de retour", ->
    p = stage_probe.new!
    mod = {}
    mod.f = -> 1, nil, 3
    p.wrap mod, "f", "f"
    a, b, c = mod.f!
    assert.same 1, a
    assert.is_nil b
    assert.same 3, c

  it "wrap_state enveloppe les méthodes des états rendus", ->
    p = stage_probe.new!
    mod = { new: -> { get: (-> 7), put: (-> 8) } }
    p.wrap_state mod, "new", { "get" }
    st = mod.new!
    assert.same 7, st.get!
    assert.same 8, st.put!
    labels = p.labels!
    assert.same { "so.get" }, labels

  it "reset remet les compteurs à zéro", ->
    p = stage_probe.new!
    mod = { f: -> 1 }
    p.wrap mod, "f", "f"
    mod.f!
    p.reset!
    assert.same 0, p.results(1)[1].calls

  it "wrap refuse un champ absent ou non-fonction", ->
    p = stage_probe.new!
    assert.is_false p.wrap { x: 3 }, "x", "x"
    assert.is_false p.wrap nil, "x", "x"
