local ffi = require("ffi")
local orig_ffi = ffi
local proxy_C = setmetatable({
  __errno_location = function()
    return orig_ffi.new("int[1]", 2)
  end
}, {
  __index = function(self, k)
    return orig_ffi.C[k]
  end
})
local ffi_proxy = setmetatable({
  C = proxy_C,
  load = function(...)
    return orig_ffi.load(...)
  end,
  cdef = function(...)
    return orig_ffi.cdef(...)
  end,
  new = function(...)
    return orig_ffi.new(...)
  end,
  sizeof = function(...)
    return orig_ffi.sizeof(...)
  end,
  string = function(...)
    return orig_ffi.string(...)
  end,
  copy = function(...)
    return orig_ffi.copy(...)
  end,
  fill = function(...)
    return orig_ffi.fill(...)
  end,
  cast = function(...)
    return orig_ffi.cast(...)
  end,
  typeof = function(...)
    return orig_ffi.typeof(...)
  end,
  istype = function(...)
    return orig_ffi.istype(...)
  end,
  errno = function(...)
    return orig_ffi.errno(...)
  end
}, {
  __index = function(self, k)
    return orig_ffi[k]
  end
})
package.loaded["ffi"] = ffi_proxy
local pbkdf2, hash_password, verify_password, load_secrets, valid_username, register_user
do
  local _obj_0 = require("auth.credentials")
  pbkdf2, hash_password, verify_password, load_secrets, valid_username, register_user = _obj_0.pbkdf2, _obj_0.hash_password, _obj_0.verify_password, _obj_0.load_secrets, _obj_0.valid_username, _obj_0.register_user
end
package.loaded["ffi"] = orig_ffi
return describe("auth/credentials", function()
  describe("pbkdf2", function()
    it("vecteur RFC 6070 (password, salt, iter=1)", function()
      local hash = pbkdf2("password", "73616c74", 1)
      return assert.equals("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b", hash)
    end)
    return it("hash_password + verify_password round-trip", function()
      local stored = hash_password("testpass")
      assert.is_true(verify_password("testpass", stored))
      return assert.is_false(verify_password("wrong", stored))
    end)
  end)
  describe("verify_password", function()
    it("mot de passe correct", function()
      return assert.is_true(verify_password("mypassword", hash_password("mypassword")))
    end)
    it("mauvais mot de passe", function()
      return assert.is_false(verify_password("wrongpassword", hash_password("mypassword")))
    end)
    return it("format hash invalide → faux", function()
      assert.is_false(verify_password("x", "badformat"))
      return assert.is_false(verify_password("x", "md5:1000:salt:hash"))
    end)
  end)
  describe("valid_username", function()
    it("adresses email valides", function()
      assert.is_true(valid_username("user@domain.com"))
      return assert.is_true(valid_username("a.b-c+d@sub.domain.co.uk"))
    end)
    return it("adresses invalides", function()
      assert.is_false(valid_username("nodomain"))
      assert.is_false(valid_username("@nodomain"))
      assert.is_false(valid_username("a@b"))
      assert.is_false(valid_username((string.rep("x", 65) .. "@d.com")))
      return assert.is_false(valid_username("ab"))
    end)
  end)
  describe("load_secrets", function()
    it("lecture d'un fichier valide", function()
      local path = "tmp/test_secrets_cred_" .. os.time() .. ".txt"
      local fh = io.open(path, "w")
      fh:write("alice:pbkdf2-sha256:100000:deadbeef:cafebabe\n")
      fh:write("bob:pbkdf2-sha256:100001:beefdead:babecafe\n")
      fh:write("# commentaire\n\n")
      fh:write("charlie:pbkdf2-sha256:100002:c0ffee:badfood\n")
      fh:close()
      local secrets, err = load_secrets(path)
      assert.is_not_nil(secrets, tostring(err))
      assert.equals("pbkdf2-sha256:100000:deadbeef:cafebabe", secrets["alice"])
      assert.equals("pbkdf2-sha256:100001:beefdead:babecafe", secrets["bob"])
      assert.equals("pbkdf2-sha256:100002:c0ffee:badfood", secrets["charlie"])
      return os.remove(path)
    end)
    return it("fichier absent → nil + erreur", function()
      local secrets, err = load_secrets("/nonexistent/path")
      assert.is_nil(secrets)
      return assert.is_not_nil(err)
    end)
  end)
  return describe("register_user", function()
    it("enregistrement réussi", function()
      local path = "tmp/test_reg_" .. os.time() .. ".txt"
      local secrets, err = register_user("newuser@domain.com", "password123", path, { })
      assert.is_not_nil(secrets, tostring(err))
      assert.is_true(verify_password("password123", secrets["newuser@domain.com"]))
      return os.remove(path)
    end)
    return it("doublon → nil + message d'erreur", function()
      local path = "tmp/test_reg2_" .. os.time() .. ".txt"
      register_user("dup@domain.com", "password123", path, { })
      local secrets, err = register_user("dup@domain.com", "otherpass", path, {
        ["dup@domain.com"] = "dummy"
      })
      assert.is_nil(secrets)
      assert.truthy(err:find("déjà pris", 1, true))
      return os.remove(path)
    end)
  end)
end)
