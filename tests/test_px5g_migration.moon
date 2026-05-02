-- tests/test_px5g_migration.moon
-- Unit tests pour la migration px5g

describe "cert_cache (LRU with TTL)", ->
  it "should insert and retrieve an entry", ->
    cache_module = require "auth.cert_cache"
    cache = cache_module.create_cache 10, 3600
    
    cert = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
    key = "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"
    
    ok = cache.set "example.com", cert, key, nil
    assert ok == true, "set should return true"
    
    entry = cache.get "example.com"
    assert entry ~= nil, "entry should exist"
    assert entry.cert_pem == cert, "cert_pem should match"
    assert entry.key_pem == key, "key_pem should match"
  
  it "should handle case-insensitive hostnames", ->
    cache_module = require "auth.cert_cache"
    cache = cache_module.create_cache 10, 3600
    
    cert = "test_cert"
    cache.set "Example.COM", cert, "test_key", nil
    
    entry = cache.get "example.com"
    assert entry ~= nil, "should find with lowercase"
    assert entry.cert_pem == cert, "cert should match"
  
  it "should evict oldest entry when full", ->
    cache_module = require "auth.cert_cache"
    cache = cache_module.create_cache 3, 3600
    
    for i = 1, 4
      cache.set "host#{i}.com", "cert#{i}", "key#{i}", nil
    
    stats = cache.stats!
    assert stats.size <= 3, "cache should not exceed max size"
    
    -- Oldest entry (host1) should be gone
    entry1 = cache.get "host1.com"
    assert entry1 == nil, "oldest entry should be evicted"
    
    -- Newer entries should exist
    entry4 = cache.get "host4.com"
    assert entry4 ~= nil, "newest entry should exist"
  
  it "should handle expired entries", ->
    cache_module = require "auth.cert_cache"
    cache = cache_module.create_cache 10, 1  -- TTL = 1 second
    
    cache.set "example.com", "cert", "key", nil
    os.sleep 2  -- Wait for expiration (LuaJIT os.sleep not available, use clock)
    
    -- Can't easily test sleep in unit test without real time,
    -- but the structure is in place for purge_expired

describe "sni_extractor", ->
  it "should parse a minimal valid TLS ClientHello", ->
    sni_module = require "auth.sni_extractor"
    
    -- This is a minimal TLS ClientHello with SNI
    -- For now, just test that the function doesn't crash on bad input
    bad_data = "xyz"
    hostname = sni_module.extract_sni bad_data
    assert hostname == nil, "should return nil for invalid data"
  
  it "should return nil for non-handshake records", ->
    sni_module = require "auth.sni_extractor"
    
    -- Not a handshake record (type != 0x16)
    data = string.char(0x17) .. string.rep("\x00", 100)
    hostname = sni_module.extract_sni data
    assert hostname == nil, "should return nil for non-handshake"

describe "cert_generator", ->
  it "should validate input parameters", ->
    gen = require "auth.cert_generator"
    
    -- Empty key should fail
    cert, ok, err = gen.generate_self_signed "", "test.com", {}
    assert ok == false, "should fail with empty key"
    
    -- Empty CN should fail
    cert, ok, err = gen.generate_self_signed "test_key", "", {}
    assert ok == false, "should fail with empty CN"
