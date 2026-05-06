-- tests/unit/auth/cert_generator_spec.moon
-- Tests de auth/cert_generator (wrapper px5g).
-- Le test de génération effective est skippé si px5g n'est pas installé.

cg = require "auth.cert_generator"
{ :generate_self_signed, :generate_rsa_key } = cg

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
    key_pem, cert_pem, ok, err = generate_self_signed "example.com"
    assert.is_true ok, tostring(err)
    assert.is_not_nil key_pem
    assert.is_not_nil cert_pem

  it "CN valide avec jours explicites → chemin nominal px5g", ->
    -- Couvre: days = tonumber(days) avec valeur non-nil, cmd building avec CN+days
    key_pem, cert_pem, ok, err = generate_self_signed "test.local", {}, 365
    assert.is_true ok, tostring(err)
    assert.is_not_nil key_pem
    assert.is_not_nil cert_pem

  it "module se charge sans crash même si px5g absent", ->
    -- Vérifie que require "auth.cert_generator" ne plante pas
    mod = require "auth.cert_generator"
    assert.is_not_nil mod
    assert.is_function mod.generate_self_signed
    assert.is_function mod.generate_rsa_key

  -- ═══════════════════════════════════════════════════════════════════════════
  -- generate_rsa_key — branches sans px5g
  -- px5g absent → io.popen réussit (shell trouve la commande mais px5g n'existe pas)
  -- → lecture vide + handle:close() retourne nil → branche "not close_ok"
  -- ═══════════════════════════════════════════════════════════════════════════

  it "generate_rsa_key sans argument → bits=2048 par défaut → erreur px5g", ->
    -- Couvre: bits==nil → bits=2048, cmd building, io.popen, handle:read, handle:close
    -- Avec px5g absent: close_ok=nil → branche not close_ok → retourne nil, false, err
    key_pem, ok, err = generate_rsa_key!
    assert.is_nil key_pem
    assert.is_false ok
    assert.is_not_nil err
    assert.is_string err

  it "generate_rsa_key avec bits entier → tonumber(bits) non-nil", ->
    -- Couvre: bits = tonumber(bits) or 2048 avec bits non-nil
    key_pem, ok, err = generate_rsa_key 4096
    assert.is_nil key_pem
    assert.is_false ok
    assert.is_string err

  it "generate_rsa_key avec bits=nil → bits=2048", ->
    -- Même chemin que sans argument: bits==nil → bits=2048
    key_pem, ok, err = generate_rsa_key nil
    assert.is_nil key_pem
    assert.is_false ok
    assert.is_string err

  it "generate_rsa_key avec bits string → tonumber conversion", ->
    -- bits = "2048" (string) → tonumber("2048") = 2048 → cmd = "px5g rsakey 2048"
    key_pem, ok, err = generate_rsa_key "2048"
    assert.is_nil key_pem
    assert.is_false ok
    assert.is_string err

  -- ═══════════════════════════════════════════════════════════════════════════
  -- generate_rsa_key — branches avec io.popen mocké
  -- On injecte des faux handles pour couvrir les branches output vide et PEM invalide
  -- ═══════════════════════════════════════════════════════════════════════════

  describe "generate_rsa_key avec io.popen mocké", ->
    local orig_popen

    before_each ->
      orig_popen = io.popen

    after_each ->
      io.popen = orig_popen

    it "close_ok=nil → branche not close_ok → erreur rsakey failed", ->
      -- Force handle:close() = nil pour déclencher la branche "not close_ok"
      io.popen = (cmd) ->
        {
          read: (self, fmt) -> ""
          close: (self) -> nil
        }
      key_pem, ok, err = generate_rsa_key 2048
      assert.is_nil key_pem
      assert.is_false ok
      assert.is_string err

    it "key_pem vide + close_ok=true → branche empty output", ->
      -- Couvre: if not (key_pem and #key_pem > 0) → "px5g rsakey produced empty output"
      io.popen = (cmd) ->
        {
          read: (self, fmt) -> ""
          close: (self) -> true
        }
      key_pem, ok, err = generate_rsa_key 2048
      assert.is_nil key_pem
      assert.is_false ok
      assert.is_string err
      assert.is_true err\find("empty", 1, true) != nil

    it "key_pem non-PEM + close_ok=true → PEM invalide", ->
      -- Couvre: if not (key_pem:match("BEGIN.*PRIVATE KEY")) → "not valid PEM"
      io.popen = (cmd) ->
        {
          read: (self, fmt) -> "not a valid PEM output"
          close: (self) -> true
        }
      key_pem, ok, err = generate_rsa_key 2048
      assert.is_nil key_pem
      assert.is_false ok
      assert.is_string err
      assert.is_true err\find("not valid PEM", 1, true) != nil

    it "key_pem PEM valide + close_ok=true → succès (log_debug + return)", ->
      -- Couvre le chemin de succès: log_debug({...}) + return key_pem, true, nil
      fake_pem = "-----BEGIN RSA PRIVATE KEY-----\nfakedata\n-----END RSA PRIVATE KEY-----\n"
      io.popen = (cmd) ->
        {
          read: (self, fmt) -> fake_pem
          close: (self) -> true
        }
      key_pem, ok, err = generate_rsa_key 2048
      assert.is_not_nil key_pem
      assert.is_true ok
      assert.is_nil err
      assert.are.equal fake_pem, key_pem

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
