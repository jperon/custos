-- tests/suite_px5g.moon
-- Tests unitaires pour cert_cache, cert_generator, cert.

ffi = require "ffi"
tf = require "test_framework"
{ :test, :run_suite, :assert_eq, :assert_ne, :assert_true, :assert_false,
  :assert_nil, :assert_not_nil, :assert_contains } = tf

package.loaded["log"] = {
  log_debug: ->
  log_warn:  ->
  log_error: ->
}

-- ── cert_cache ──────────────────────────────────────────────────────

{ :create_cache } = require "auth.cert_cache"

px5g_tests = {
  { "cert_cache insert + get", ->
    cache = create_cache 10, 3600, "tmp/test_certs"
    cache.clear!
    cert = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
    key  = "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"
    assert_true cache.set("example.com", cert, key, nil)
    entry = cache.get("example.com")
    assert_not_nil entry
    assert_eq entry.cert_pem, cert
    assert_eq entry.key_pem, key
  }

  { "cert_cache case-insensitive", ->
    cache = create_cache 10, 3600, "tmp/test_certs2"
    cache.clear!
    cache.set("Example.COM", "CERT", "KEY", nil)
    entry = cache.get("example.com")
    assert_not_nil entry
    assert_eq entry.cert_pem, "CERT"
  }

  { "cert_cache LRU eviction RAM", ->
    cache = create_cache 3, 3600, "tmp/test_certs3"
    cache.clear!
    for i = 1, 4
      cache.set("host#{i}.com", "cert#{i}", "key#{i}", nil)
    s = cache.stats!
    assert_eq s.size_ram, 3, "RAM ne doit pas dépasser max_size"
  }

  { "cert_cache persistance disque", ->
    dir = "tmp/test_certs4"
    cache = create_cache 10, 3600, dir
    cache.clear!
    cache.set("persist.test", "MYCERT", "MYKEY", nil)

    -- Nouveau cache, même répertoire
    cache2 = create_cache 10, 3600, dir
    entry = cache2.get("persist.test")
    assert_not_nil entry, "devrait charger depuis disque"
    assert_eq entry.cert_pem, "MYCERT"
    assert_eq entry.key_pem, "MYKEY"
  }

  { "cert_cache expiration via get", ->
    -- Vérifie que get() retourne nil si l'index persistant indique expiration
    dir = "tmp/test_certs_ttl"
    cache = create_cache 10, 3600, dir
    cache.clear!
    cache.set("expire.test", "CERT", "KEY", nil)
    -- Modifier l'index persistant pour mettre une expiration dans le passé
    idx_path = "tmp/cert_cache_index.lua"
    fh = io.open idx_path, "w"
    fh\write 'return { ["expire.test"] = { expires_at=1, accessed_at=1 } }\n'
    fh\close!
    -- Recharger un nouveau cache (charge le nouvel index)
    cache2 = create_cache 10, 3600, dir
    entry = cache2.get("expire.test")
    assert_nil entry, "devrait être expiré selon l'index"
  }
}

-- ── cert_generator ────────────────────────────────────────────────

{ :generate_self_signed } = require "auth.cert_generator"

px5g_tests2 = {
  { "generate_self_signed paramètres invalides", ->
    cert, key, ok, err = generate_self_signed "", {}, 365
    assert_false ok
    assert_not_nil err
  }

  { "generate_self_signed CN valide (si px5g présent)", ->
    -- Vérifie si px5g est disponible
    f = io.popen "which px5g 2>/dev/null"
    has_px5g = f and (f\read "*l") and true or false
    f\close! if f

    unless has_px5g
      print "    SKIP: px5g non installé"
      return

    cert, key, ok, err = generate_self_signed "test.example.com", {}, 365
    assert_true ok, err
    assert_not_nil cert
    assert_not_nil key
    assert_contains cert, "BEGIN CERTIFICATE"
    assert_contains key, "BEGIN"
  }
}

-- ── cert ──────────────────────────────────────────────────────────

{ :hash_string } = require "auth.cert"

cert_tests = {
  { "hash_string déterministe", ->
    h1 = hash_string "hello"
    h2 = hash_string "hello"
    assert_eq h1, h2
  }

  { "hash_string différente entrées", ->
    h1 = hash_string "a"
    h2 = hash_string "b"
    assert_ne h1, h2
  }
}

run_suite "auth/cert_cache", px5g_tests
run_suite "auth/cert_generator", px5g_tests2
run_suite "auth/cert", cert_tests

tf.summary!
os.exit (tf.failed > 0) and 1 or 0
