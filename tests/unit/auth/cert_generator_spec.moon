-- tests/unit/auth/cert_generator_spec.moon
-- Tests de auth/cert_generator (wrapper px5g).
-- Le test de génération effective est skippé si px5g n'est pas installé.

{ :generate_self_signed } = require "auth.cert_generator"

describe "auth/cert_generator", ->

  it "paramètres invalides → ok=false", ->
    cert, key, ok, err = generate_self_signed "", {}, 365
    assert.is_false ok
    assert.is_not_nil err

  it "génération avec px5g si disponible #px5g", ->
    f       = io.popen "which px5g 2>/dev/null"
    has_px5g = f and (f\read("*l") ~= nil) or false
    if f then f\close!

    pending "px5g non installé" unless has_px5g

    cert, key, ok, err = generate_self_signed "test.example.com", {}, 365
    assert.is_true ok, tostring(err)
    assert.is_not_nil cert
    assert.is_not_nil key
    assert.truthy cert\find("BEGIN CERTIFICATE", 1, true)
    assert.truthy key\find("BEGIN", 1, true)
