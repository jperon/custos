-- tests/unit/auth/resolve_tls_ctx_spec.moon
-- Vérifie la sélection du contexte TLS par connexion.
-- Optimisation : le contexte statique hérité du parent (via fork COW) est
-- réutilisé tel quel, SANS relecture disque ni reconstruction par connexion.

{ :resolve_tls_ctx } = require "auth.server"

describe "auth/server resolve_tls_ctx", ->

  it "réutilise le contexte statique hérité sans recharger depuis le disque", ->
    inherited = { tag: "inherited-ctx" }
    counters = { static: 0, sni: 0 }
    fake_load_static = (key, cert) ->
      counters.static += 1
      { tag: "reloaded" }
    fake_sni = (ip, cache) ->
      counters.sni += 1
      { tag: "sni" }
    state = { static_tls_ctx: inherited, static_cert_paths: { cert: "c", key: "k" } }
    ctx = resolve_tls_ctx state, "203.0.113.1", fake_load_static, fake_sni
    assert.equals inherited, ctx       -- même objet, hérité
    assert.equals 0, counters.static   -- aucun rechargement disque
    assert.equals 0, counters.sni      -- aucune génération

  it "repli sur load_static si le contexte hérité est absent", ->
    reloaded = { tag: "reloaded" }
    counters = { static: 0 }
    fake_load_static = (key, cert) ->
      counters.static += 1
      reloaded
    fake_sni = (ip, cache) -> error "ne doit pas générer de cert SNI"
    state = { static_cert_paths: { cert: "c", key: "k" } }
    ctx = resolve_tls_ctx state, "203.0.113.1", fake_load_static, fake_sni
    assert.equals reloaded, ctx
    assert.equals 1, counters.static

  it "lève si le repli load_static échoue", ->
    fail_load_static = (key, cert) -> nil, "fichier introuvable"
    fake_sni = (ip, cache) -> error "ne doit pas générer de cert SNI"
    state = { static_cert_paths: { cert: "c", key: "k" } }
    ok = pcall resolve_tls_ctx, state, "203.0.113.1", fail_load_static, fake_sni
    assert.is_false ok

  it "génère/charge un cert SNI dynamique si aucun cert statique n'est configuré", ->
    sni = { tag: "sni" }
    counters = { sni: 0 }
    fail_load_static = (key, cert) -> error "ne doit pas charger de cert statique"
    fake_sni = (ip, cache) ->
      counters.sni += 1
      sni
    state = { cert_cache: {} }
    ctx = resolve_tls_ctx state, "203.0.113.1", fail_load_static, fake_sni
    assert.equals sni, ctx
    assert.equals 1, counters.sni
