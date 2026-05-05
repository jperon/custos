local ffi = require("ffi")
local tf = require("test_framework")
local test, run_suite, assert_eq, assert_ne, assert_true, assert_false, assert_nil, assert_not_nil, assert_contains
test, run_suite, assert_eq, assert_ne, assert_true, assert_false, assert_nil, assert_not_nil, assert_contains = tf.test, tf.run_suite, tf.assert_eq, tf.assert_ne, tf.assert_true, tf.assert_false, tf.assert_nil, tf.assert_not_nil, tf.assert_contains
package.loaded["log"] = {
  log_debug = function() end,
  log_warn = function() end,
  log_error = function() end
}
local create_cache
create_cache = require("auth.cert_cache").create_cache
local px5g_tests = {
  {
    "cert_cache insert + get",
    function()
      local cache = create_cache(10, 3600, "tmp/test_certs")
      cache.clear()
      local cert = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
      local key = "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"
      assert_true(cache.set("example.com", cert, key, nil))
      local entry = cache.get("example.com")
      assert_not_nil(entry)
      assert_eq(entry.cert_pem, cert)
      return assert_eq(entry.key_pem, key)
    end
  },
  {
    "cert_cache case-insensitive",
    function()
      local cache = create_cache(10, 3600, "tmp/test_certs2")
      cache.clear()
      cache.set("Example.COM", "CERT", "KEY", nil)
      local entry = cache.get("example.com")
      assert_not_nil(entry)
      return assert_eq(entry.cert_pem, "CERT")
    end
  },
  {
    "cert_cache LRU eviction RAM",
    function()
      local cache = create_cache(3, 3600, "tmp/test_certs3")
      cache.clear()
      for i = 1, 4 do
        cache.set("host" .. tostring(i) .. ".com", "cert" .. tostring(i), "key" .. tostring(i), nil)
      end
      local s = cache.stats()
      return assert_eq(s.size_ram, 3, "RAM ne doit pas dépasser max_size")
    end
  },
  {
    "cert_cache persistance disque",
    function()
      local dir = "tmp/test_certs4"
      local cache = create_cache(10, 3600, dir)
      cache.clear()
      cache.set("persist.test", "MYCERT", "MYKEY", nil)
      local cache2 = create_cache(10, 3600, dir)
      local entry = cache2.get("persist.test")
      assert_not_nil(entry, "devrait charger depuis disque")
      assert_eq(entry.cert_pem, "MYCERT")
      return assert_eq(entry.key_pem, "MYKEY")
    end
  },
  {
    "cert_cache expiration via get",
    function()
      local dir = "tmp/test_certs_ttl"
      local cache = create_cache(10, 3600, dir)
      cache.clear()
      cache.set("expire.test", "CERT", "KEY", nil)
      local idx_path = "tmp/cert_cache_index.lua"
      local fh = io.open(idx_path, "w")
      fh:write('return { ["expire.test"] = { expires_at=1, accessed_at=1 } }\n')
      fh:close()
      local cache2 = create_cache(10, 3600, dir)
      local entry = cache2.get("expire.test")
      return assert_nil(entry, "devrait être expiré selon l'index")
    end
  }
}
local generate_self_signed
generate_self_signed = require("auth.cert_generator").generate_self_signed
local px5g_tests2 = {
  {
    "generate_self_signed paramètres invalides",
    function()
      local cert, key, ok, err = generate_self_signed("", { }, 365)
      assert_false(ok)
      return assert_not_nil(err)
    end
  },
  {
    "generate_self_signed CN valide (si px5g présent)",
    function()
      local f = io.popen("which px5g 2>/dev/null")
      local has_px5g = f and (f:read("*l")) and true or false
      if f then
        f:close()
      end
      if not (has_px5g) then
        print("    SKIP: px5g non installé")
        return 
      end
      local cert, key, ok, err = generate_self_signed("test.example.com", { }, 365)
      assert_true(ok, err)
      assert_not_nil(cert)
      assert_not_nil(key)
      assert_contains(cert, "BEGIN CERTIFICATE")
      return assert_contains(key, "BEGIN")
    end
  }
}
local hash_string
hash_string = require("auth.cert").hash_string
local cert_tests = {
  {
    "hash_string déterministe",
    function()
      local h1 = hash_string("hello")
      local h2 = hash_string("hello")
      return assert_eq(h1, h2)
    end
  },
  {
    "hash_string différente entrées",
    function()
      local h1 = hash_string("a")
      local h2 = hash_string("b")
      return assert_ne(h1, h2)
    end
  }
}
run_suite("auth/cert_cache", px5g_tests)
run_suite("auth/cert_generator", px5g_tests2)
run_suite("auth/cert", cert_tests)
tf.summary()
return os.exit((tf.failed > 0) and 1 or 0)
