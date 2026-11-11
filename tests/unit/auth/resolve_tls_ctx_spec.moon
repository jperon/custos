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

  -- ── Sélection par SNI demandé, repli IP ───────────────────────────────────

  it "utilise le SNI validé comme nom du certificat dynamique", ->
    seen = nil
    fake_sni = (name, cache) ->
      seen = name
      { tag: "sni" }
    fake_load_static = (key, cert) -> error "pas de statique"
    state = { cert_cache: {} }
    ctx = resolve_tls_ctx state, "203.0.113.1", fake_load_static, fake_sni, "Portal.Example"
    assert.equals "portal.example", seen, "nom normalisé en minuscules"
    assert.equals "sni", ctx.tag

  it "repli sur l'IP locale sans SNI", ->
    seen = nil
    fake_sni = (name, cache) -> seen = name
    fake_load_static = (key, cert) -> error "pas de statique"
    state = { cert_cache: {} }
    resolve_tls_ctx state, "203.0.113.1", fake_load_static, fake_sni, nil
    assert.equals "203.0.113.1", seen

  it "repli sur l'IP locale pour un SNI invalide (chemin, IP, trop long)", ->
    for bad in *{"../etc/passwd", "203.0.113.9", string.rep("a", 64) .. ".example"}
      seen = nil
      fake_sni = (name, cache) -> seen = name
      fake_load_static = (key, cert) -> error "pas de statique"
      state = { cert_cache: {} }
      resolve_tls_ctx state, "198.51.100.10", fake_load_static, fake_sni, bad
      assert.equals "198.51.100.10", seen, "SNI refusé : #{bad}"

  it "repli sur l'IP locale si la génération pour le SNI échoue", ->
    names = {}
    fake_sni = (name, cache) ->
      table.insert names, name
      error "px5g a échoué" unless name == "198.51.100.10"
      { tag: "ip-ctx" }
    fake_load_static = (key, cert) -> error "pas de statique"
    state = { cert_cache: {} }
    ctx = resolve_tls_ctx state, "198.51.100.10", fake_load_static, fake_sni, "broken.example"
    assert.same { "broken.example", "198.51.100.10" }, names
    assert.equals "ip-ctx", ctx.tag

  it "repli sur l'IP locale quand le quota de noms du cache est atteint", ->
    seen = nil
    fake_sni = (name, cache) -> seen = name
    fake_load_static = (key, cert) -> error "pas de statique"
    state = { cert_cache: { can_store: (name) -> false } }
    resolve_tls_ctx state, "198.51.100.10", fake_load_static, fake_sni, "extra.example"
    assert.equals "198.51.100.10", seen, "aucune génération pour un nom hors quota"

  it "le certificat statique reste prioritaire et n'extrait aucun SNI", ->
    inherited = { tag: "static" }
    counts = { static: 0, sni: 0 }
    fake_load_static = (k, c) -> counts.static += 1
    fake_sni = (name, cache) -> counts.sni += 1
    state = { static_tls_ctx: inherited }
    ctx = resolve_tls_ctx state, "203.0.113.1", fake_load_static, fake_sni, "portal.example"
    assert.equals inherited, ctx
    assert.equals 0, counts.static
    assert.equals 0, counts.sni
