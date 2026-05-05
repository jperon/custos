-- tests/unit/auth/cert_spec.moon
-- Tests des utilitaires de auth/cert (hash_string).

{ :hash_string } = require "auth.cert"

describe "auth/cert", ->

  it "hash_string est déterministe", ->
    assert.equals hash_string("hello"), hash_string("hello")

  it "hash_string produit des valeurs différentes pour des entrées différentes", ->
    assert.not_equals hash_string("a"), hash_string("b")
