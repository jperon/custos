local cg = require("auth.cert_generator")
local generate_self_signed, generate_rsa_key
generate_self_signed, generate_rsa_key = cg.generate_self_signed, cg.generate_rsa_key
return describe("auth/cert_generator", function()
  it("paramètres invalides → ok=false", function()
    local cert, key, ok, err = generate_self_signed("", { }, 365)
    assert.is_false(ok)
    return assert.is_not_nil(err)
  end)
  it("CN nil → ok=false", function()
    local cert, key, ok, err = generate_self_signed(nil)
    assert.is_false(ok)
    assert.is_not_nil(err)
    return assert.is_string(err)
  end)
  it("CN vide avec sans et jours → ok=false", function()
    local cert, key, ok, err = generate_self_signed("", {
      "alt.example.com"
    }, 30)
    assert.is_false(ok)
    return assert.is_not_nil(err)
  end)
  it("sans=nil et jours=nil → valeurs par défaut → succès (chemin nominal)", function()
    local key_pem, cert_pem, ok, err = generate_self_signed("example.com")
    assert.is_true(ok, tostring(err))
    assert.is_not_nil(key_pem)
    return assert.is_not_nil(cert_pem)
  end)
  it("CN valide avec jours explicites → chemin nominal px5g", function()
    local key_pem, cert_pem, ok, err = generate_self_signed("test.local", { }, 365)
    assert.is_true(ok, tostring(err))
    assert.is_not_nil(key_pem)
    return assert.is_not_nil(cert_pem)
  end)
  it("module se charge sans crash même si px5g absent", function()
    local mod = require("auth.cert_generator")
    assert.is_not_nil(mod)
    assert.is_function(mod.generate_self_signed)
    return assert.is_function(mod.generate_rsa_key)
  end)
  it("generate_rsa_key sans argument → bits=2048 par défaut → erreur px5g", function()
    local key_pem, ok, err = generate_rsa_key()
    assert.is_nil(key_pem)
    assert.is_false(ok)
    assert.is_not_nil(err)
    return assert.is_string(err)
  end)
  it("generate_rsa_key avec bits entier → tonumber(bits) non-nil", function()
    local key_pem, ok, err = generate_rsa_key(4096)
    assert.is_nil(key_pem)
    assert.is_false(ok)
    return assert.is_string(err)
  end)
  it("generate_rsa_key avec bits=nil → bits=2048", function()
    local key_pem, ok, err = generate_rsa_key(nil)
    assert.is_nil(key_pem)
    assert.is_false(ok)
    return assert.is_string(err)
  end)
  it("generate_rsa_key avec bits string → tonumber conversion", function()
    local key_pem, ok, err = generate_rsa_key("2048")
    assert.is_nil(key_pem)
    assert.is_false(ok)
    return assert.is_string(err)
  end)
  describe("generate_rsa_key avec io.popen mocké", function()
    local orig_popen
    before_each(function()
      orig_popen = io.popen
    end)
    after_each(function()
      io.popen = orig_popen
    end)
    it("close_ok=nil → branche not close_ok → erreur rsakey failed", function()
      io.popen = function(cmd)
        return {
          read = function(self, fmt)
            return ""
          end,
          close = function(self)
            return nil
          end
        }
      end
      local key_pem, ok, err = generate_rsa_key(2048)
      assert.is_nil(key_pem)
      assert.is_false(ok)
      return assert.is_string(err)
    end)
    it("key_pem vide + close_ok=true → branche empty output", function()
      io.popen = function(cmd)
        return {
          read = function(self, fmt)
            return ""
          end,
          close = function(self)
            return true
          end
        }
      end
      local key_pem, ok, err = generate_rsa_key(2048)
      assert.is_nil(key_pem)
      assert.is_false(ok)
      assert.is_string(err)
      return assert.is_true(err:find("empty", 1, true) ~= nil)
    end)
    it("key_pem non-PEM + close_ok=true → PEM invalide", function()
      io.popen = function(cmd)
        return {
          read = function(self, fmt)
            return "not a valid PEM output"
          end,
          close = function(self)
            return true
          end
        }
      end
      local key_pem, ok, err = generate_rsa_key(2048)
      assert.is_nil(key_pem)
      assert.is_false(ok)
      assert.is_string(err)
      return assert.is_true(err:find("not valid PEM", 1, true) ~= nil)
    end)
    return it("key_pem PEM valide + close_ok=true → succès (log_debug + return)", function()
      local fake_pem = "-----BEGIN RSA PRIVATE KEY-----\nfakedata\n-----END RSA PRIVATE KEY-----\n"
      io.popen = function(cmd)
        return {
          read = function(self, fmt)
            return fake_pem
          end,
          close = function(self)
            return true
          end
        }
      end
      local key_pem, ok, err = generate_rsa_key(2048)
      assert.is_not_nil(key_pem)
      assert.is_true(ok)
      assert.is_nil(err)
      return assert.are.equal(fake_pem, key_pem)
    end)
  end)
  return it("génération avec px5g si disponible #px5g", function()
    local f = io.popen("which px5g 2>/dev/null")
    local has_px5g = f and (f:read("*l") ~= nil) or false
    if f then
      f:close()
    end
    if not (has_px5g) then
      pending("px5g non installé")
    end
    local key_pem, cert_pem, ok, err = generate_self_signed("test.example.com", { }, 365)
    assert.is_true(ok, tostring(err))
    assert.is_not_nil(key_pem)
    assert.is_not_nil(cert_pem)
    assert.truthy(cert_pem:find("BEGIN CERTIFICATE", 1, true))
    return assert.truthy(key_pem:find("BEGIN", 1, true))
  end)
end)
