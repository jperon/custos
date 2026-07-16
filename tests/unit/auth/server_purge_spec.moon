-- tests/unit/auth/server_purge_spec.moon
-- Tests de auth.server.should_purge_cert_cache (fonction pure).
--
-- Contexte : purge_expired du cache de certificats n'était jamais appelé
-- (cf. AGENTS.md § px5g). Le SNI client permet de forcer la génération d'un
-- fichier .crt/.key par SNI distinct présenté sur le port 443 ; sans purge
-- périodique, ces fichiers s'accumulent indéfiniment (épuisement de la
-- flash sur un routeur embarqué).

{ :should_purge_cert_cache } = require "auth.server"

describe "auth.server.should_purge_cert_cache", ->

  it "faux avant l'intervalle", ->
    assert.is_false should_purge_cert_cache 1000, 500, 1000

  it "vrai exactement à l'intervalle", ->
    assert.is_true should_purge_cert_cache 1500, 500, 1000

  it "vrai au-delà de l'intervalle", ->
    assert.is_true should_purge_cert_cache 3000, 500, 1000

  it "vrai dès le premier tour si last_run == now (interval 0)", ->
    assert.is_true should_purge_cert_cache 1000, 1000, 0
