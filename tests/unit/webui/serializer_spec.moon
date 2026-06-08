-- tests/unit/webui/serializer_spec.moon
-- Tests de webui/serializer : sérialisation round-trip de la configuration.

{ :serialize_config, :write_config, :read_config } = require "webui.serializer"

TMP_PATH = "tmp/serializer_spec_test.moon"

describe "webui/serializer", ->

  -- ── serialize_config ────────────────────────────────────────────────────

  describe "serialize_config", ->

    it "produit une table MoonScript '{ ... }\\n'", ->
      out = serialize_config { foo: "bar" }
      assert.truthy out\find("^{", 1)
      assert.falsy out\find("^return", 1)
      -- format MoonScript : 'clé: valeur', pas 'clé = valeur'
      assert.truthy out\find("foo: ", 1, true)
      assert.falsy out\find("foo =", 1, true)
      assert.truthy out\sub(-1) == "\n"

    it "sérialise une chaîne", ->
      out = serialize_config { key: "hello" }
      assert.truthy out\find('"hello"', 1, true)

    it "sérialise un nombre entier", ->
      out = serialize_config { n: 42 }
      assert.truthy out\find("42", 1, true)

    it "sérialise un booléen true", ->
      out = serialize_config { flag: true }
      assert.truthy out\find("true", 1, true)

    it "sérialise un booléen false", ->
      out = serialize_config { flag: false }
      assert.truthy out\find("false", 1, true)

    it "sérialise nil comme nil", ->
      out = serialize_config { x: nil }
      -- la clé n'est pas incluse dans la table
      assert.falsy out\find('"x"', 1, true)

    it "sérialise un tableau (array)", ->
      out = serialize_config { list: { "a", "b", "c" } }
      assert.truthy out\find('"a"', 1, true)
      assert.truthy out\find('"b"', 1, true)
      assert.truthy out\find('"c"', 1, true)
      -- doit utiliser la forme tableau { "a", "b", "c" }
      assert.truthy out\find('{ "a", "b", "c" }', 1, true)

    it "sérialise une table imbriquée de façon déterministe", ->
      out = serialize_config { runtime: { log_level: "INFO", benchmark: false } }
      assert.truthy out\find("runtime", 1, true)
      assert.truthy out\find("log_level", 1, true)
      assert.truthy out\find('"INFO"', 1, true)
      assert.truthy out\find("benchmark", 1, true)

    it "trie les clés de façon déterministe", ->
      out1 = serialize_config { z: 1, a: 2, m: 3 }
      out2 = serialize_config { m: 3, z: 1, a: 2 }
      assert.equals out1, out2

    it "table vide → '{}'", ->
      out = serialize_config {}
      assert.truthy out\find("{}", 1, true)

    it "clé avec caractères spéciaux → notation ['...']", ->
      cfg = {}
      cfg["some-key"] = "val"
      out = serialize_config cfg
      assert.truthy out\find('["some-key"]', 1, true)

  -- ── write_config + read_config ───────────────────────────────────────────

  describe "write_config + read_config (round-trip)", ->

    after_each ->
      os.remove TMP_PATH
      os.remove TMP_PATH .. ".webui.new"

    it "écrit et relit une config simple", ->
      cfg = { runtime: { log_level: "DEBUG" }, dns: { port: 53 } }
      ok, err = write_config cfg, TMP_PATH
      assert.is_true ok
      assert.is_nil err
      loaded, err2 = read_config TMP_PATH
      assert.is_nil err2
      assert.not_nil loaded
      assert.equals "DEBUG", loaded.runtime.log_level
      assert.equals 53, loaded.dns.port

    it "round-trip préserve les booléens", ->
      cfg = { auth: { enabled: true, tls: false } }
      write_config cfg, TMP_PATH
      loaded = (read_config TMP_PATH)
      assert.is_true loaded.auth.enabled
      assert.is_false loaded.auth.tls

    it "round-trip préserve les tableaux", ->
      cfg = { filter: { allowed: { "example.com", "test.org" } } }
      write_config cfg, TMP_PATH
      loaded = (read_config TMP_PATH)
      assert.equals "example.com", loaded.filter.allowed[1]
      assert.equals "test.org",    loaded.filter.allowed[2]

    it "round-trip préserve les tables imbriquées", ->
      cfg = { nft: { family: "bridge", table: "dns-filter" } }
      write_config cfg, TMP_PATH
      loaded = (read_config TMP_PATH)
      assert.equals "bridge",     loaded.nft.family
      assert.equals "dns-filter", loaded.nft.table

    it "le fichier .webui.new temporaire est supprimé après écriture atomique", ->
      write_config { x: 1 }, TMP_PATH
      fh = io.open TMP_PATH .. ".webui.new", "r"
      assert.is_nil fh  -- le fichier tmp ne doit plus exister

    it "retourne une erreur si le chemin est invalide", ->
      ok, err = write_config { x: 1 }, "/nonexistent/dir/file.moon"
      assert.is_nil ok
      assert.not_nil err

    it "retourne nil+erreur si le fichier n'existe pas", ->
      loaded, err = read_config "/nonexistent/config.moon"
      assert.is_nil loaded
      assert.not_nil err

    it "le fichier écrit est du MoonScript chargeable par moonscript.base.loadfile", ->
      -- Vérifie le chargement concret tel que le fait le runtime (et non via
      -- read_config), pour garantir que la sortie est bien du MoonScript valide.
      cfg = {
        runtime: { log_level: "DEBUG", benchmark: false }
        filter: {
          rules: {
            { description: "règle accentuée é", actions: { "allow" } }
          }
          nets: { lan: { "192.168.0.0/16", "10.0.0.0/8" } }
        }
      }
      cfg["clé-spéciale"] = "valeur"
      ok = write_config cfg, TMP_PATH
      assert.is_true ok
      -- Le fichier ne doit PAS être du Lua (`key = value` / `return`)
      fh = assert io.open TMP_PATH, "r"
      content = fh\read "*a"
      fh\close!
      assert.falsy content\find("return", 1, true)
      assert.falsy content\find("log_level =", 1, true)
      assert.truthy content\find("log_level:", 1, true)
      -- Chargement concret via le loader MoonScript
      moon_base = require "moonscript.base"
      fn, err = moon_base.loadfile TMP_PATH
      assert.is_nil err
      assert.not_nil fn
      loaded = fn!
      assert.equals "DEBUG", loaded.runtime.log_level
      assert.is_false loaded.runtime.benchmark
      assert.equals "règle accentuée é", loaded.filter.rules[1].description
      assert.equals "10.0.0.0/8", loaded.filter.nets.lan[2]
      assert.equals "valeur", loaded["clé-spéciale"]

    it "round-trip complet avec toutes les sections de base", ->
      cfg = {
        runtime:     { log_level: "WARN", benchmark: true }
        nft:         { family: "bridge", table: "t", set_ip4: "s4", set_ip6: "s6" }
        filter: {
          rules: {
            { description: "règle 1", actions: { "allow" } }
            { description: "règle 2", actions: { "block" } }
          }
          nets:  { local: { "192.168.0.0/16" } }
        }
      }
      write_config cfg, TMP_PATH
      loaded = (read_config TMP_PATH)
      assert.equals "WARN",   loaded.runtime.log_level
      assert.is_true          loaded.runtime.benchmark
      assert.equals "règle 1", loaded.filter.rules[1].description
      assert.equals "allow",  loaded.filter.rules[1].actions[1]
      assert.equals "192.168.0.0/16", loaded.filter.nets.local[1]
