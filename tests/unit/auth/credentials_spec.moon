-- tests/unit/auth/credentials_spec.moon
-- Tests des fonctions pures de auth/credentials (pbkdf2, verify_password,
-- valid_username, load_secrets, register_user).
-- Pas de FFI, pas de root requis.

ffi = require "ffi"

-- ── Proxy FFI pour éviter __errno_location manquant dans certains env ──────
orig_ffi = ffi
proxy_C = setmetatable {
  __errno_location: -> orig_ffi.new("int[1]", 2)
}, __index: (k) => orig_ffi.C[k]
ffi_proxy = setmetatable {
  C:       proxy_C
  load:    (...) -> orig_ffi.load ...
  cdef:    (...) -> orig_ffi.cdef ...
  new:     (...) -> orig_ffi.new ...
  sizeof:  (...) -> orig_ffi.sizeof ...
  string:  (...) -> orig_ffi.string ...
  copy:    (...) -> orig_ffi.copy ...
  fill:    (...) -> orig_ffi.fill ...
  cast:    (...) -> orig_ffi.cast ...
  typeof:  (...) -> orig_ffi.typeof ...
  istype:  (...) -> orig_ffi.istype ...
  errno:   (...) -> orig_ffi.errno ...
}, __index: (k) => orig_ffi[k]
package.loaded["ffi"] = ffi_proxy

{ :pbkdf2, :hash_password, :verify_password,
  :load_secrets, :valid_username, :register_user } = require "auth.credentials"

-- Restaure le vrai ffi pour les autres specs
package.loaded["ffi"] = orig_ffi

describe "auth/credentials", ->

  describe "pbkdf2", ->
    it "vecteur RFC 6070 (password, salt, iter=1)", ->
      hash = pbkdf2 "password", "73616c74", 1  -- "salt" en hex
      assert.equals "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b", hash

    it "hash_password + verify_password round-trip", ->
      stored = hash_password "testpass"
      assert.is_true verify_password("testpass", stored)
      assert.is_false verify_password("wrong", stored)

  describe "verify_password", ->
    it "mot de passe correct", ->
      assert.is_true verify_password("mypassword", hash_password("mypassword"))

    it "mauvais mot de passe", ->
      assert.is_false verify_password("wrongpassword", hash_password("mypassword"))

    it "format hash invalide → faux", ->
      assert.is_false verify_password("x", "badformat")
      assert.is_false verify_password("x", "md5:1000:salt:hash")

  describe "valid_username", ->
    it "adresses email valides", ->
      assert.is_true valid_username "user@domain.com"
      assert.is_true valid_username "a.b-c+d@sub.domain.co.uk"

    it "adresses invalides", ->
      assert.is_false valid_username "nodomain"
      assert.is_false valid_username "@nodomain"
      assert.is_false valid_username "a@b"
      assert.is_false valid_username (string.rep("x", 65) .. "@d.com")
      assert.is_false valid_username "ab"

  describe "load_secrets", ->
    it "lecture d'un fichier valide", ->
      path = "tmp/test_secrets_cred_" .. os.time! .. ".txt"
      fh = io.open path, "w"
      fh\write "alice:pbkdf2-sha256:100000:deadbeef:cafebabe\n"
      fh\write "bob:pbkdf2-sha256:100001:beefdead:babecafe\n"
      fh\write "# commentaire\n\n"
      fh\write "charlie:pbkdf2-sha256:100002:c0ffee:badfood\n"
      fh\close!
      secrets, err = load_secrets path
      assert.is_not_nil secrets, tostring(err)
      assert.equals "pbkdf2-sha256:100000:deadbeef:cafebabe", secrets["alice"]
      assert.equals "pbkdf2-sha256:100001:beefdead:babecafe", secrets["bob"]
      assert.equals "pbkdf2-sha256:100002:c0ffee:badfood",   secrets["charlie"]
      os.remove path

    it "fichier absent → nil + erreur", ->
      secrets, err = load_secrets "/nonexistent/path"
      assert.is_nil secrets
      assert.is_not_nil err

  describe "register_user", ->
    it "enregistrement réussi", ->
      path = "tmp/test_reg_" .. os.time! .. ".txt"
      secrets, err = register_user "newuser@domain.com", "password123", path, {}
      assert.is_not_nil secrets, tostring(err)
      assert.is_true verify_password("password123", secrets["newuser@domain.com"])
      os.remove path

    it "doublon → nil + message d'erreur", ->
      path = "tmp/test_reg2_" .. os.time! .. ".txt"
      register_user "dup@domain.com", "password123", path, {}
      secrets, err = register_user "dup@domain.com", "otherpass", path,
        { ["dup@domain.com"]: "dummy" }
      assert.is_nil secrets
      assert.truthy err\find("déjà pris", 1, true)
      os.remove path
