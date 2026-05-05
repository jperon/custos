-- tests/unit/auth/cert_cache_spec.moon
-- Tests du cache LRU/TTL de certificats (auth/cert_cache).
-- Pas de FFI, pas de root requis.

{ :create_cache } = require "auth.cert_cache"

CERT = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
KEY  = "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"

describe "auth/cert_cache", ->

  it "insert + get basique", ->
    cache = create_cache 10, 3600, "tmp/test_certs_u1"
    cache.clear!
    assert.is_true cache.set("example.com", CERT, KEY, nil)
    entry = cache.get("example.com")
    assert.is_not_nil entry
    assert.equals CERT, entry.cert_pem
    assert.equals KEY,  entry.key_pem

  it "insensible à la casse", ->
    cache = create_cache 10, 3600, "tmp/test_certs_u2"
    cache.clear!
    cache.set("Example.COM", "CERT", "KEY", nil)
    entry = cache.get("example.com")
    assert.is_not_nil entry
    assert.equals "CERT", entry.cert_pem

  it "éviction LRU (max_size=3)", ->
    cache = create_cache 3, 3600, "tmp/test_certs_u3"
    cache.clear!
    for i = 1, 4
      cache.set("host#{i}.com", "cert#{i}", "key#{i}", nil)
    s = cache.stats!
    assert.equals 3, s.size_ram

  it "persistance disque entre instances", ->
    dir   = "tmp/test_certs_u4"
    cache = create_cache 10, 3600, dir
    cache.clear!
    cache.set("persist.unit", "MYCERT", "MYKEY", nil)
    cache2 = create_cache 10, 3600, dir
    entry = cache2.get("persist.unit")
    assert.is_not_nil entry, "doit charger depuis disque"
    assert.equals "MYCERT", entry.cert_pem
    assert.equals "MYKEY",  entry.key_pem

  it "get retourne nil si l'index indique expiration", ->
    dir = "tmp/test_certs_u5"
    cache = create_cache 10, 3600, dir
    cache.clear!
    cache.set("expire.unit", "CERT", "KEY", nil)
    -- Écraser l'index avec une expiration dans le passé
    idx_path = "tmp/cert_cache_index.lua"
    fh = io.open idx_path, "w"
    fh\write 'return { ["expire.unit"] = { expires_at=1, accessed_at=1 } }\n'
    fh\close!
    cache2 = create_cache 10, 3600, dir
    assert.is_nil cache2.get("expire.unit")
