local cg = require("auth.cert_generator")
local generate_self_signed, generate_rsa_key
generate_self_signed, generate_rsa_key = cg.generate_self_signed, cg.generate_rsa_key
local has_px5g
has_px5g = function()
  local f = io.popen("command -v px5g 2>/dev/null")
  if not (f) then
    return false
  end
  local found = f:read("*l") ~= nil
  f:close()
  return found
end
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
    local f = io.popen("command -v px5g 2>/dev/null")
    local has = f and (f:read("*l") ~= nil)
    if f then
      f:close()
    end
    if not (has) then
      pending("px5g non installé")
    end
    local key_pem, cert_pem, ok, err = generate_self_signed("example.com")
    assert.is_true(ok, tostring(err))
    assert.is_not_nil(key_pem)
    return assert.is_not_nil(cert_pem)
  end)
  it("CN valide avec jours explicites → chemin nominal px5g", function()
    local f = io.popen("command -v px5g 2>/dev/null")
    local has = f and (f:read("*l") ~= nil)
    if f then
      f:close()
    end
    if not (has) then
      pending("px5g non installé")
    end
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
  local assert_rsa_result
  assert_rsa_result = function(key_pem, ok, err)
    if has_px5g() then
      assert.is_true(ok, tostring(err))
      assert.is_string(key_pem)
      return assert.is_not_nil(key_pem:match("BEGIN.*PRIVATE KEY"))
    else
      assert.is_nil(key_pem)
      assert.is_false(ok)
      return assert.is_string(err)
    end
  end
  it("generate_rsa_key sans argument → bits=2048 par défaut", function()
    return assert_rsa_result(generate_rsa_key())
  end)
  it("generate_rsa_key avec bits entier → tonumber(bits) non-nil", function()
    return assert_rsa_result(generate_rsa_key(4096))
  end)
  it("generate_rsa_key avec bits=nil → bits=2048", function()
    return assert_rsa_result(generate_rsa_key(nil))
  end)
  it("generate_rsa_key avec bits string → tonumber conversion", function()
    return assert_rsa_result(generate_rsa_key("2048"))
  end)
  describe("generate_rsa_key avec os.execute/io.open mockés", function()
    local orig_execute, orig_open
    local mock_px5g
    mock_px5g = function(exit_code, file_content)
      os.execute = function(cmd)
        return exit_code
      end
      io.open = function(path, mode)
        if not (file_content ~= nil) then
          return nil
        end
        return {
          read = function(self, fmt)
            return file_content
          end,
          close = function(self)
            return true
          end
        }
      end
    end
    before_each(function()
      orig_execute = os.execute
      orig_open = io.open
    end)
    after_each(function()
      os.execute = orig_execute
      io.open = orig_open
    end)
    it("exit code non-zéro → branche erreur px5g", function()
      mock_px5g(1, nil)
      local key_pem, ok, err = generate_rsa_key(2048)
      assert.is_nil(key_pem)
      assert.is_false(ok)
      assert.is_string(err)
      return assert.is_true(err:find("error code", 1, true) ~= nil)
    end)
    it("succès mais fichier illisible → branche read failed", function()
      mock_px5g(0, nil)
      local key_pem, ok, err = generate_rsa_key(2048)
      assert.is_nil(key_pem)
      assert.is_false(ok)
      assert.is_string(err)
      return assert.is_true(err:find("Cannot read", 1, true) ~= nil)
    end)
    it("fichier vide → branche empty output", function()
      mock_px5g(0, "")
      local key_pem, ok, err = generate_rsa_key(2048)
      assert.is_nil(key_pem)
      assert.is_false(ok)
      assert.is_string(err)
      return assert.is_true(err:find("empty", 1, true) ~= nil)
    end)
    it("fichier non-PEM → branche PEM invalide", function()
      mock_px5g(0, "not a valid PEM output")
      local key_pem, ok, err = generate_rsa_key(2048)
      assert.is_nil(key_pem)
      assert.is_false(ok)
      assert.is_string(err)
      return assert.is_true(err:find("not valid PEM", 1, true) ~= nil)
    end)
    return it("fichier PEM valide → succès (log_debug + return)", function()
      local fake_pem = "-----BEGIN RSA PRIVATE KEY-----\nfakedata\n-----END RSA PRIVATE KEY-----\n"
      mock_px5g(0, fake_pem)
      local key_pem, ok, err = generate_rsa_key(2048)
      assert.is_not_nil(key_pem)
      assert.is_true(ok)
      assert.is_nil(err)
      return assert.are.equal(fake_pem, key_pem)
    end)
  end)
  return it("génération avec px5g si disponible #px5g", function()
    local f = io.popen("which px5g 2>/dev/null")
    has_px5g = f and (f:read("*l") ~= nil) or false
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
