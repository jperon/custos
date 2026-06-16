-- tests/unit/bench/report_spec.moon
-- Tests des fonctions pures de bench/report : percentiles, (dé)sérialisation
-- baseline, calcul de deltas, formatage texte.

report = require "bench.report"
{ :percentiles, :serialize, :deserialize, :deltas, :format } = report

describe "bench/report", ->

  describe "percentiles", ->
    it "échantillons connus → p50/p95/p99/min/max", ->
      samples = [ i for i = 1, 100 ]  -- 1..100
      p = percentiles samples
      assert.equal 1, p.min
      assert.equal 100, p.max
      -- p50 = valeur à l'indice ceil(0.50*100)=50
      assert.equal 50, p.p50
      assert.equal 95, p.p95
      assert.equal 99, p.p99

    it "liste vide → champs à 0", ->
      p = percentiles {}
      assert.equal 0, p.p50
      assert.equal 0, p.p99
      assert.equal 0, p.count

    it "ne modifie pas l'ordre de la table source (copie avant tri)", ->
      samples = { 3, 1, 2 }
      percentiles samples
      assert.same { 3, 1, 2 }, samples

    it "compte les échantillons", ->
      assert.equal 3, (percentiles { 5, 7, 9 }).count

  describe "serialize / deserialize", ->
    it "aller-retour préserve une table imbriquée", ->
      result = {
        ts: "2026-06-16T00:00:00"
        micro: { { name: "parse", ns_per_op: 12.5, kb_alloc: 3 } }
        load: { qps: 1000, p50: 1.2, p99: 9.9 }
      }
      round = deserialize serialize result
      assert.same result, round

    it "deserialize d'une chaîne invalide → nil + err", ->
      r, err = deserialize "ceci n'est pas une table"
      assert.is_nil r
      assert.is_string err

  describe "deltas", ->
    it "calcule le pourcentage de variation par métrique", ->
      cur  = { qps: 1100, p99: 8.0 }
      base = { qps: 1000, p99: 10.0 }
      d = deltas cur, base
      assert.equal 10, d.qps      -- +10 %
      assert.equal -20, d.p99     -- -20 %

    it "baseline à 0 → delta nil (évite division par zéro)", ->
      d = deltas { qps: 5 }, { qps: 0 }
      assert.is_nil d.qps

    it "métrique absente du baseline → ignorée", ->
      d = deltas { qps: 5, nouveau: 3 }, { qps: 5 }
      assert.is_nil d.nouveau

  describe "format", ->
    it "produit un rapport texte mentionnant les métriques de charge", ->
      result = { load: { qps: 1234, p50: 1.0, p95: 5.0, p99: 9.0, sent: 10, received: 9, dropped: 1, timeouts: 0 } }
      txt = format result
      assert.truthy txt\find "1234"
      assert.truthy txt\find "qps", 1, true

    it "avec baseline, affiche les deltas %", ->
      cur  = { load: { qps: 1100 } }
      base = { load: { qps: 1000 } }
      txt = format cur, base
      assert.truthy txt\find "%%"  -- un signe pourcent quelque part
