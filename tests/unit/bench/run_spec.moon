-- tests/unit/bench/run_spec.moon
-- Tests du parseur d'arguments de l'orchestrateur bench.

runner = require "bench.run"
{ :parse_args, :load_domains, :main } = runner

describe "bench/run", ->

  describe "load_domains", ->
    it "nil → nil", ->
      assert.is_nil load_domains nil

    it "lit un fichier en ignorant vides et commentaires", ->
      path = "tmp/bench-domains-test.txt"
      f = io.open path, "w"
      f\write "a.com\n\n# commentaire\n  b.com  \n"
      f\close!
      d = load_domains path
      assert.same { "a.com", "b.com" }, d
      os.remove path

    it "fichier absent → nil", ->
      assert.is_nil load_domains "tmp/nope-#{os.time!}.txt"

  describe "main", ->
    it "volet micro seul → result.micro peuplé, pas de result.load", ->
      r = main { "--micro", "--iters", "1000" }
      assert.is_truthy r.micro
      assert.is_nil r.load
      assert.is_string r.ts

    it "--save-baseline écrit la baseline rechargeable", ->
      main { "--micro", "--iters", "1000", "--save-baseline" }
      f = io.open "tmp/bench/baseline.lua", "r"
      assert.is_truthy f
      content = f\read "*a"
      f\close!
      assert.truthy content\find "return", 1, true

  describe "parse_args", ->
    it "valeurs par défaut : micro seul", ->
      o = parse_args {}
      assert.is_true o.micro
      assert.is_false o.load

    it "--load active le volet charge", ->
      o = parse_args { "--load" }
      assert.is_true o.load

    it "--all active les deux volets", ->
      o = parse_args { "--all" }
      assert.is_true o.micro
      assert.is_true o.load

    it "--target host:port est découpé", ->
      o = parse_args { "--load", "--target", "10.0.0.2:5353" }
      assert.equal "10.0.0.2", o.target
      assert.equal 5353, o.port

    it "--target sans port garde 53 par défaut", ->
      o = parse_args { "--target", "10.0.0.2" }
      assert.equal "10.0.0.2", o.target
      assert.equal 53, o.port

    it "--duration / --rate / --iters sont numériques", ->
      o = parse_args { "--duration", "10", "--rate", "500", "--iters", "2000" }
      assert.equal 10, o.duration
      assert.equal 500, o.rate
      assert.equal 2000, o.iters

    it "--save-baseline active le flag", ->
      o = parse_args { "--save-baseline" }
      assert.is_true o.save_baseline

    it "--domains capture le chemin de fichier", ->
      o = parse_args { "--domains", "tmp/d.txt" }
      assert.equal "tmp/d.txt", o.domains_file
