-- tests/unit/auth/cert_generator_spec.moon
-- Tests de auth/cert_generator (wrapper px5g).
-- Le test de génération effective est skippé si px5g n'est pas installé.

cg = require "auth.cert_generator"
{ :generate_self_signed, :generate_rsa_key } = cg

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
    assert.is_function mod.generate_rsa_key

  -- ═══════════════════════════════════════════════════════════════════════════
  -- generate_rsa_key — chemin nominal (gestion des arguments bits)
  -- px5g présent → clé PEM valide ; absent → branche d'erreur.
  -- Les branches d'erreur fines sont couvertes plus bas via io.popen mocké.
  -- ═══════════════════════════════════════════════════════════════════════════

  -- Vérifie le résultat selon la disponibilité de px5g.
  assert_rsa_result = (key_pem, ok, err) ->
    if has_px5g!
      assert.is_true ok, tostring(err)
      assert.is_string key_pem
      assert.is_not_nil key_pem\match("BEGIN.*PRIVATE KEY")
    else
      assert.is_nil key_pem
      assert.is_false ok
      assert.is_string err

  it "generate_rsa_key sans argument → bits=2048 par défaut", ->
    -- Couvre: bits==nil → bits=2048, cmd building, io.popen, handle:read, handle:close
    assert_rsa_result generate_rsa_key!

  it "generate_rsa_key avec bits entier → tonumber(bits) non-nil", ->
    -- Couvre: bits = tonumber(bits) or 2048 avec bits non-nil
    assert_rsa_result generate_rsa_key 4096

  it "generate_rsa_key avec bits=nil → bits=2048", ->
    -- Même chemin que sans argument: bits==nil → bits=2048
    assert_rsa_result generate_rsa_key nil

  it "generate_rsa_key avec bits string → tonumber conversion", ->
    -- bits = "2048" (string) → tonumber("2048") = 2048 → cmd = "px5g rsakey 2048"
    assert_rsa_result generate_rsa_key "2048"

  -- ═══════════════════════════════════════════════════════════════════════════
  -- generate_rsa_key — branches avec os.execute + io.open mockés
  -- px5g écrit la clé dans un fichier (-out) ; on simule exit code + contenu fichier.
  -- ═══════════════════════════════════════════════════════════════════════════

  describe "generate_rsa_key avec os.execute/io.open mockés", ->
    local orig_execute, orig_open

    -- Installe des mocks : px5g « réussit » avec exit_code, et le fichier lu
    -- renvoie file_content (ou io.open renvoie nil si file_content == nil).
    mock_px5g = (exit_code, file_content) ->
      os.execute = (cmd) -> exit_code
      io.open = (path, mode) ->
        return nil unless file_content != nil
        {
          read:  (self, fmt) -> file_content
          close: (self) -> true
        }

    before_each ->
      orig_execute = os.execute
      orig_open    = io.open

    after_each ->
      os.execute = orig_execute
      io.open    = orig_open

    it "exit code non-zéro → branche erreur px5g", ->
      mock_px5g 1, nil
      key_pem, ok, err = generate_rsa_key 2048
      assert.is_nil key_pem
      assert.is_false ok
      assert.is_string err
      assert.is_true err\find("error code", 1, true) != nil

    it "succès mais fichier illisible → branche read failed", ->
      -- exit_code ok mais io.open renvoie nil
      mock_px5g 0, nil
      key_pem, ok, err = generate_rsa_key 2048
      assert.is_nil key_pem
      assert.is_false ok
      assert.is_string err
      assert.is_true err\find("Cannot read", 1, true) != nil

    it "fichier vide → branche empty output", ->
      mock_px5g 0, ""
      key_pem, ok, err = generate_rsa_key 2048
      assert.is_nil key_pem
      assert.is_false ok
      assert.is_string err
      assert.is_true err\find("empty", 1, true) != nil

    it "fichier non-PEM → branche PEM invalide", ->
      mock_px5g 0, "not a valid PEM output"
      key_pem, ok, err = generate_rsa_key 2048
      assert.is_nil key_pem
      assert.is_false ok
      assert.is_string err
      assert.is_true err\find("not valid PEM", 1, true) != nil

    it "fichier PEM valide → succès (log_debug + return)", ->
      fake_pem = "-----BEGIN RSA PRIVATE KEY-----\nfakedata\n-----END RSA PRIVATE KEY-----\n"
      mock_px5g 0, fake_pem
      key_pem, ok, err = generate_rsa_key 2048
      assert.is_not_nil key_pem
      assert.is_true ok
      assert.is_nil err
      assert.are.equal fake_pem, key_pem

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
