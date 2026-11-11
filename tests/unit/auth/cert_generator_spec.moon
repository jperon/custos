-- tests/unit/auth/cert_generator_spec.moon
-- Tests de auth/cert_generator (wrapper px5g).
-- Le test de génération effective est skippé si px5g n'est pas installé.

cg = require "auth.cert_generator"
{ :generate_self_signed } = cg

-- px5g est désormais fourni par le flake (dépendance obligatoire). On teste donc
-- le chemin nominal quand il est présent, et la branche d'erreur sinon.
has_px5g = ->
  f = io.popen "command -v px5g 2>/dev/null"
  return false unless f
  found = f\read("*l") != nil
  f\close!
  found

describe "auth/cert_generator", ->

  -- ═══════════════════════════════════════════════════════════════════════════
  -- generate_self_signed — branches sans px5g
  -- ═══════════════════════════════════════════════════════════════════════════

  it "paramètres invalides → ok=false", ->
    cert, key, ok, err = generate_self_signed "", {}, 365
    assert.is_false ok
    assert.is_not_nil err

  it "CN nil → ok=false", ->
    cert, key, ok, err = generate_self_signed nil
    assert.is_false ok
    assert.is_not_nil err
    assert.is_string err

  it "CN vide avec sans et jours → ok=false", ->
    cert, key, ok, err = generate_self_signed "", {"alt.example.com"}, 30
    assert.is_false ok
    assert.is_not_nil err

  it "sans=nil et jours=nil → valeurs par défaut → succès (chemin nominal)", ->
    -- Couvre: if sans == nil → sans={}, if days == nil → days=3650
    -- puis days = tonumber(days), cmd building, os.execute, lecture fichiers
    f = io.popen "command -v px5g 2>/dev/null"
    has = f and (f\read("*l") ~= nil)
    f\close! if f
    pending "px5g non installé" unless has
    key_pem, cert_pem, ok, err = generate_self_signed "example.com"
    assert.is_true ok, tostring(err)
    assert.is_not_nil key_pem
    assert.is_not_nil cert_pem

  it "CN valide avec jours explicites → chemin nominal px5g", ->
    -- Couvre: days = tonumber(days) avec valeur non-nil, cmd building avec CN+days
    f = io.popen "command -v px5g 2>/dev/null"
    has = f and (f\read("*l") ~= nil)
    f\close! if f
    pending "px5g non installé" unless has
    key_pem, cert_pem, ok, err = generate_self_signed "test.local", {}, 365
    assert.is_true ok, tostring(err)
    assert.is_not_nil key_pem
    assert.is_not_nil cert_pem

  it "module se charge sans crash même si px5g absent", ->
    -- Vérifie que require "auth.cert_generator" ne plante pas
    mod = require "auth.cert_generator"
    assert.is_not_nil mod
    assert.is_function mod.generate_self_signed

  -- ═══════════════════════════════════════════════════════════════════════════
  -- generate_self_signed — branches d'erreur avec os.execute + io.open mockés
  -- px5g écrit deux fichiers (clé puis certificat) ; on simule exit code et le
  -- contenu de chaque fichier selon le chemin (key_file / cert_file).
  -- ═══════════════════════════════════════════════════════════════════════════

  describe "generate_self_signed avec os.execute/io.open mockés", ->
    local orig_execute, orig_open

    -- exit_code : code de retour px5g ; key_content / cert_content : contenu lu
    -- (nil → io.open renvoie nil pour ce fichier, simulant un échec d'ouverture).
    mock_px5g = (exit_code, key_content, cert_content) ->
      os.execute = (cmd) -> exit_code
      io.open = (path, mode) ->
        content = if path\find("key", 1, true) then key_content else cert_content
        return nil if content == nil
        {
          read:  (self, fmt) -> content
          close: (self) -> true
        }

    before_each ->
      orig_execute = os.execute
      orig_open    = io.open

    after_each ->
      os.execute = orig_execute
      io.open    = orig_open

    it "exit code non-zéro → branche erreur px5g", ->
      mock_px5g 1, nil, nil
      key, cert, ok, err = generate_self_signed "example.com"
      assert.is_nil key
      assert.is_nil cert
      assert.is_false ok
      assert.is_true err\find("error code", 1, true) != nil

    it "clé illisible → branche key_read_failed", ->
      mock_px5g 0, nil, "cert"
      key, cert, ok, err = generate_self_signed "example.com"
      assert.is_false ok
      assert.is_true err\find("Cannot read generated key", 1, true) != nil

    it "clé vide → branche key_empty", ->
      mock_px5g 0, "", "cert"
      key, cert, ok, err = generate_self_signed "example.com"
      assert.is_false ok
      assert.is_true err\find("empty key", 1, true) != nil

    it "certificat illisible → branche cert_read_failed", ->
      mock_px5g 0, "-----BEGIN EC PRIVATE KEY-----\nx\n-----END EC PRIVATE KEY-----\n", nil
      key, cert, ok, err = generate_self_signed "example.com"
      assert.is_false ok
      assert.is_true err\find("Cannot read generated cert", 1, true) != nil

    it "certificat vide → branche cert_empty", ->
      mock_px5g 0, "-----BEGIN EC PRIVATE KEY-----\nx\n-----END EC PRIVATE KEY-----\n", ""
      key, cert, ok, err = generate_self_signed "example.com"
      assert.is_false ok
      assert.is_true err\find("empty cert", 1, true) != nil

    it "clé + certificat valides → succès", ->
      fake_key  = "-----BEGIN EC PRIVATE KEY-----\nk\n-----END EC PRIVATE KEY-----\n"
      fake_cert = "-----BEGIN CERTIFICATE-----\nc\n-----END CERTIFICATE-----\n"
      mock_px5g 0, fake_key, fake_cert
      key, cert, ok, err = generate_self_signed "example.com", {"a.example.com"}, 365
      assert.is_true ok, tostring(err)
      assert.are.equal fake_key, key
      assert.are.equal fake_cert, cert
      assert.is_nil err

    -- Régression anti-collision PRNG : sans math.randomseed (jamais fait dans
    -- ce projet), deux enfants forkés au même os.time! avec le même état PRNG
    -- hérité produiraient le même math.random(...) et donc le même nom de
    -- fichier temporaire, s'écrasant mutuellement leur cert/clé en cours de
    -- génération. Avec os.time! ET math.random figés à une valeur constante
    -- (simule deux enfants forkés identiques), le nom doit rester unique.
    it "reste unique même à os.time!/math.random figés (simule deux enfants forkés identiques)", ->
      fake_key  = "-----BEGIN EC PRIVATE KEY-----\nk\n-----END EC PRIVATE KEY-----\n"
      fake_cert = "-----BEGIN CERTIFICATE-----\nc\n-----END CERTIFICATE-----\n"
      orig_time, orig_random = os.time, math.random
      os.time     = -> 1000000
      math.random = (n) -> 42
      seen_paths  = {}
      os.execute  = (cmd) ->
        path = cmd\match "%-keyout ([^%s]+)"
        seen_paths[#seen_paths + 1] = path
        0
      io.open = (path, mode) ->
        {
          read:  (self, fmt) -> (path\find "key", 1, true) and fake_key or fake_cert
          close: (self) -> true
        }
      generate_self_signed "example.com"
      generate_self_signed "example.com"
      os.time, math.random = orig_time, orig_random
      assert.equals 2, #seen_paths
      assert.are_not.equal seen_paths[1], seen_paths[2]

  it "génération avec px5g si disponible #px5g", ->
    f       = io.popen "which px5g 2>/dev/null"
    has_px5g = f and (f\read("*l") ~= nil) or false
    if f then f\close!

    pending "px5g non installé" unless has_px5g

    -- generate_self_signed retourne : key_pem, cert_pem, ok, err
    key_pem, cert_pem, ok, err = generate_self_signed "test.example.com", {}, 365
    assert.is_true ok, tostring(err)
    assert.is_not_nil key_pem
    assert.is_not_nil cert_pem
    assert.truthy cert_pem\find("BEGIN CERTIFICATE", 1, true)
    assert.truthy key_pem\find("BEGIN", 1, true)
