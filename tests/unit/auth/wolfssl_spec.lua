local ssl_ok, ssl = pcall(require, "auth.ffi_wolfssl")
return describe("auth/ffi_wolfssl", function()
  if not ssl_ok then
    it("libwolfssl non disponible", function()
      return pending("libwolfssl non disponible")
    end)
    return 
  end
  describe("exports du module", function()
    it("newcontext est une fonction", function()
      return assert.equals("function", type(ssl.newcontext))
    end)
    it("wrap est une fonction", function()
      return assert.equals("function", type(ssl.wrap))
    end)
    it("free_context est une fonction", function()
      return assert.equals("function", type(ssl.free_context))
    end)
    return it("libwolfssl est chargé (non nil)", function()
      return assert.is_not_nil(ssl.libwolfssl)
    end)
  end)
  describe("constantes d'erreur SSL", function()
    it("SSL_ERROR_NONE vaut 0", function()
      return assert.equals(0, ssl.SSL_ERROR_NONE)
    end)
    it("SSL_ERROR_WANT_READ est un nombre", function()
      return assert.equals("number", type(ssl.SSL_ERROR_WANT_READ))
    end)
    it("SSL_ERROR_WANT_WRITE est un nombre", function()
      return assert.equals("number", type(ssl.SSL_ERROR_WANT_WRITE))
    end)
    it("SSL_ERROR_SSL est un nombre", function()
      return assert.equals("number", type(ssl.SSL_ERROR_SSL))
    end)
    return it("les constantes sont toutes distinctes", function()
      local vals = {
        ssl.SSL_ERROR_NONE,
        ssl.SSL_ERROR_WANT_READ,
        ssl.SSL_ERROR_WANT_WRITE,
        ssl.SSL_ERROR_SSL
      }
      local seen = { }
      for _index_0 = 1, #vals do
        local v = vals[_index_0]
        assert.is_nil(seen[v], "constante dupliquée : " .. tostring(v))
        seen[v] = true
      end
    end)
  end)
  describe("newcontext validation des arguments", function()
    it("newcontext({}) lève une erreur (certificate manquant)", function()
      local ok, err = pcall(ssl.newcontext, { })
      assert.is_false(ok)
      return assert.is_not_nil(err)
    end)
    it("newcontext sans table lève une erreur", function()
      local ok, err = pcall(ssl.newcontext, nil)
      assert.is_false(ok)
      return assert.is_not_nil(err)
    end)
    return it("newcontext avec chemins inexistants échoue proprement", function()
      local ok, err = pcall(ssl.newcontext, {
        certificate = "/nonexistent/cert.pem",
        key = "/nonexistent/key.pem"
      })
      if not ok then
        return assert.is_not_nil(err)
      end
    end)
  end)
  return describe("compatibilité socket + ssl (module chain)", function()
    it("socket.tcp est disponible", function()
      local sock_mod = require("lib.socket")
      return assert.equals("function", type(sock_mod.tcp))
    end)
    return it("ssl.newcontext et socket.tcp sont indépendants", function()
      local sock_mod = require("lib.socket")
      local ok, sock = pcall(sock_mod.tcp)
      assert.is_true(ok)
      if ok and sock then
        sock:close()
      end
      return assert.equals("function", type(ssl.newcontext))
    end)
  end)
end)
