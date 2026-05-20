-- tests/unit/auth/wolfssl_spec.moon
-- Spec Busted pour auth.ffi_wolfssl (exports, constantes, appelabilité).
-- Les tests de handshake TLS complet nécessitent des certificats valides
-- et sont couverts par les tests E2E.

ssl_ok, ssl = pcall require, "auth.ffi_wolfssl"

describe "auth/ffi_wolfssl", ->
  if not ssl_ok
    it "libwolfssl non disponible", -> pending "libwolfssl non disponible"
    return

  describe "exports du module", ->
    it "newcontext est une fonction", ->
      assert.equals "function", type ssl.newcontext

    it "wrap est une fonction", ->
      assert.equals "function", type ssl.wrap

    it "free_context est une fonction", ->
      assert.equals "function", type ssl.free_context

    it "libwolfssl est chargé (non nil)", ->
      assert.is_not_nil ssl.libwolfssl

  describe "constantes d'erreur SSL", ->
    it "SSL_ERROR_NONE vaut 0", ->
      assert.equals 0, ssl.SSL_ERROR_NONE

    it "SSL_ERROR_WANT_READ est un nombre", ->
      assert.equals "number", type ssl.SSL_ERROR_WANT_READ

    it "SSL_ERROR_WANT_WRITE est un nombre", ->
      assert.equals "number", type ssl.SSL_ERROR_WANT_WRITE

    it "SSL_ERROR_SSL est un nombre", ->
      assert.equals "number", type ssl.SSL_ERROR_SSL

    it "les constantes sont toutes distinctes", ->
      vals = { ssl.SSL_ERROR_NONE, ssl.SSL_ERROR_WANT_READ,
               ssl.SSL_ERROR_WANT_WRITE, ssl.SSL_ERROR_SSL }
      seen = {}
      for v in *vals
        assert.is_nil seen[v], "constante dupliquée : #{v}"
        seen[v] = true

  describe "newcontext validation des arguments", ->
    it "newcontext({}) lève une erreur (certificate manquant)", ->
      ok, err = pcall ssl.newcontext, {}
      assert.is_false ok
      assert.is_not_nil err

    it "newcontext sans table lève une erreur", ->
      ok, err = pcall ssl.newcontext, nil
      assert.is_false ok
      assert.is_not_nil err

    it "newcontext avec chemins inexistants échoue proprement", ->
      ok, err = pcall ssl.newcontext, {
        certificate: "/nonexistent/cert.pem",
        key:         "/nonexistent/key.pem"
      }
      -- wolfssl retourne une erreur ou nil, pas un crash
      assert.is_not_nil err if not ok

  describe "compatibilité socket + ssl (module chain)", ->
    it "socket.tcp est disponible", ->
      sock_mod = require "lib.socket"
      assert.equals "function", type sock_mod.tcp

    it "ssl.newcontext et socket.tcp sont indépendants", ->
      sock_mod = require "lib.socket"
      ok, sock = pcall sock_mod.tcp
      assert.is_true ok
      sock\close! if ok and sock
      -- newcontext reste accessible après création de socket
      assert.equals "function", type ssl.newcontext
