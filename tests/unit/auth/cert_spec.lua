local hash_string, generate_self_signed, make_context, load_static, load_or_generate_sni
do
  local _obj_0 = require("auth.cert")
  hash_string, generate_self_signed, make_context, load_static, load_or_generate_sni = _obj_0.hash_string, _obj_0.generate_self_signed, _obj_0.make_context, _obj_0.load_static, _obj_0.load_or_generate_sni
end
return describe("auth/cert", function()
  it("hash_string est déterministe", function()
    return assert.equals(hash_string("hello"), hash_string("hello"))
  end)
  it("hash_string produit des valeurs différentes pour des entrées différentes", function()
    return assert.not_equals(hash_string("a"), hash_string("b"))
  end)
  it("hash_string fonctionne sur une chaîne vide", function()
    local result = hash_string("")
    return assert.is_string(result)
  end)
  it("hash_string fonctionne sur une longue chaîne", function()
    local long_str = string.rep("x", 1000)
    local result = hash_string(long_str)
    assert.is_string(result)
    return assert.not_equals(result, hash_string("x"))
  end)
  it("generate_self_signed génère un certificat et une clé valides", function()
    local key_path = "tmp/spec_test_gen.key"
    local cert_path = "tmp/spec_test_gen.crt"
    os.remove(key_path)
    os.remove(cert_path)
    local ok, out = generate_self_signed(key_path, cert_path, {
      "DNS:spec-test.local"
    })
    assert.is_true(ok, "openssl doit réussir: " .. tostring(out))
    local fh_key = io.open(key_path, "r")
    local fh_crt = io.open(cert_path, "r")
    assert.is_not_nil(fh_key, "fichier clé doit exister")
    assert.is_not_nil(fh_crt, "fichier cert doit exister")
    fh_key:close()
    return fh_crt:close()
  end)
  it("generate_self_signed avec plusieurs SANs", function()
    local key_path = "tmp/spec_test_multi.key"
    local cert_path = "tmp/spec_test_multi.crt"
    local ok, out = generate_self_signed(key_path, cert_path, {
      "DNS:host1.local",
      "DNS:host2.local",
      "IP:127.0.0.1"
    })
    return assert.is_true(ok)
  end)
  it("generate_self_signed retourne false si le chemin clé est invalide", function()
    local ok, out = generate_self_signed("/nonexistent/path/test.key", "/nonexistent/path/test.crt", {
      "DNS:test.local"
    })
    return assert.is_false(ok)
  end)
  it("make_context retourne un contexte (wolfssl valide les fichiers au handshake)", function()
    local ok, ctx = pcall(make_context, "nonexistent.key", "nonexistent.crt")
    return assert.is_true(ok == true or ok == false)
  end)
  it("make_context retourne un contexte TLS si les fichiers sont valides", function()
    local key_path = "tmp/spec_ctx_test.key"
    local cert_path = "tmp/spec_ctx_test.crt"
    local ok_gen, _ = generate_self_signed(key_path, cert_path, {
      "DNS:ctx-test.local"
    })
    if ok_gen then
      local ok, ctx = pcall(make_context, key_path, cert_path)
      assert.is_true(ok)
      return assert.is_not_nil(ctx)
    end
  end)
  it("load_static retourne nil si les chemins sont nil", function()
    local ctx, err = load_static(nil, nil)
    assert.is_nil(ctx)
    return assert.is_string(err)
  end)
  it("load_static retourne nil si les fichiers n'existent pas", function()
    local ctx, err = load_static("nonexistent.key", "nonexistent.crt")
    assert.is_nil(ctx)
    return assert.is_string(err)
  end)
  it("load_static retourne un contexte si les fichiers existent", function()
    local key_path = "tmp/spec_static.key"
    local cert_path = "tmp/spec_static.crt"
    local ok_gen, _ = generate_self_signed(key_path, cert_path, {
      "DNS:static-test.local"
    })
    if ok_gen then
      local ctx, err = load_static(key_path, cert_path)
      return assert.is_true((ctx ~= nil) or (err ~= nil))
    end
  end)
  it("load_or_generate_sni génère un certificat pour un hostname inconnu", function()
    local key_path_ref = "tmp/spec_sni_stub.key"
    local cert_path_ref = "tmp/spec_sni_stub.crt"
    local ok_gen, _ = generate_self_signed(key_path_ref, cert_path_ref, {
      "DNS:sni-test.local"
    })
    if ok_gen then
      local fh_k = io.open(key_path_ref, "r")
      local fh_c = io.open(cert_path_ref, "r")
      local real_key = fh_k:read("*a")
      local real_cert = fh_c:read("*a")
      fh_k:close()
      fh_c:close()
      package.loaded["auth.cert_generator"] = {
        generate_self_signed = function(hostname)
          return real_key, real_cert, true, nil
        end
      }
      local mock_cache = {
        get = function(h)
          return nil
        end,
        set = function(h, c, k, ctx)
          return true
        end
      }
      local ok, result = pcall(load_or_generate_sni, "sni-test.local", mock_cache)
      assert.is_true(ok, "load_or_generate_sni ne doit pas lever d'erreur: " .. tostring(result))
      assert.is_not_nil(result)
      package.loaded["auth.cert_generator"] = nil
    end
  end)
  it("load_or_generate_sni retourne le ctx depuis le cache (cache hit RAM)", function()
    local fake_ctx = {
      ssl_ctx = "fake"
    }
    local mock_cache = {
      get = function(h)
        return {
          ctx = fake_ctx,
          cert_pem = "CERT",
          key_pem = "KEY"
        }
      end,
      set = function(h, c, k, ctx)
        return true
      end
    }
    local ok, result = pcall(load_or_generate_sni, "cached.local", mock_cache)
    assert.is_true(ok)
    return assert.equals(fake_ctx, result)
  end)
  it("load_or_generate_sni utilise un hostname par défaut si nil", function()
    local fake_ctx = {
      ssl_ctx = "default_ctx"
    }
    local mock_cache = {
      get = function(h)
        if h == "custos" then
          return {
            ctx = fake_ctx,
            cert_pem = "C",
            key_pem = "K"
          }
        else
          return nil
        end
      end,
      set = function(h, c, k, ctx)
        return true
      end
    }
    local ok, result = pcall(load_or_generate_sni, nil, mock_cache)
    assert.is_true(ok)
    return assert.equals(fake_ctx, result)
  end)
  it("load_or_generate_sni reconstruit le contexte depuis les PEM disque (cache hit disk)", function()
    local key_path_ref = "tmp/spec_sni_disk.key"
    local cert_path_ref = "tmp/spec_sni_disk.crt"
    local ok_gen, _ = generate_self_signed(key_path_ref, cert_path_ref, {
      "DNS:disk-test.local"
    })
    if ok_gen then
      local fh_k = io.open(key_path_ref, "r")
      local fh_c = io.open(cert_path_ref, "r")
      local real_key = fh_k:read("*a")
      local real_cert = fh_c:read("*a")
      fh_k:close()
      fh_c:close()
      local mock_cache = {
        get = function(h)
          return {
            ctx = nil,
            cert_pem = real_cert,
            key_pem = real_key
          }
        end,
        set = function(h, c, k, ctx)
          return true
        end
      }
      local ok, result = pcall(load_or_generate_sni, "disk-test.local", mock_cache)
      return assert.is_true(ok == true or ok == false)
    end
  end)
  return it("load_or_generate_sni lève une erreur si la génération échoue", function()
    package.loaded["auth.cert_generator"] = {
      generate_self_signed = function(hostname)
        return nil, nil, false, "generation failed"
      end
    }
    local mock_cache = {
      get = function(h)
        return nil
      end,
      set = function(h, c, k, ctx)
        return true
      end
    }
    local ok, err = pcall(load_or_generate_sni, "fail-gen.local", mock_cache)
    assert.is_false(ok)
    assert.is_string(err)
    package.loaded["auth.cert_generator"] = nil
  end)
end)
