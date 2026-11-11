-- tests/unit/auth/wolfssl_spec.moon
-- Spec Busted pour auth.ffi_wolfssl (exports, constantes, appelabilité).
-- Les tests de handshake TLS complet nécessitent des certificats valides
-- et sont couverts par les tests E2E.

ssl_ok, ssl = pcall require, "auth.ffi_wolfssl"

ffi = require "ffi"

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

    it "find_ca_file est une fonction", ->
      assert.equals "function", type ssl.find_ca_file

    it "verification_available est une fonction", ->
      assert.equals "function", type ssl.verification_available

  describe "vérification du certificat (repli DoH)", ->

    it "un magasin de CA système est trouvé", ->
      ca = ssl.find_ca_file!
      assert.is_string ca
      assert.is_true #ca > 0

    it "verification_available → true avec les symboles et un magasin de CA", ->
      ok, why, ca = ssl.verification_available!
      assert.is_true ok, why
      assert.is_string ca

    it "newclient_context(verify_peer) charge le magasin de CA", ->
      ok, ctx = pcall ssl.newclient_context, { verify_peer: true }
      assert.is_true ok
      assert.is_true ctx.verify_peer
      assert.is_string ctx.ca_file
      ssl.free_context ctx

    it "newclient_context(verify_peer, ca_file inexistant) échoue proprement", ->
      ok, err = pcall ssl.newclient_context, {
        verify_peer: true
        ca_file: "/nonexistent/ca-bundle.pem"
      }
      assert.is_false ok
      assert.is_not_nil err

    it "newclient_context sans verify_peer ne charge aucun CA", ->
      ctx = ssl.newclient_context {}
      assert.is_false ctx.verify_peer
      assert.is_nil ctx.ca_file
      ssl.free_context ctx

  describe "ALPN adaptatif (h2,http/1.1)", ->

    it "préfère wolfSSL_CTX_UseALPN quand il est présent", ->
      captured = {}
      fake = {
        wolfSSL_CTX_UseALPN: (ctx, list, sz, opts) ->
          captured = { list: ffi.string(list, sz), size: sz, options: opts }
          1
      }
      mode = ssl.alpn_configure_ctx fake, "CTX"
      assert.equals "ctx", mode
      assert.equals "h2,http/1.1", captured.list
      assert.equals 11, captured.size
      assert.equals 1, captured.options

    it "repli par objet SSL quand seul wolfSSL_UseALPN existe", ->
      captured = {}
      fake = {
        wolfSSL_UseALPN: (obj, list, sz, opts) ->
          captured = { list: ffi.string(list, sz), size: sz, options: opts }
          1
      }
      assert.is_nil ssl.alpn_configure_ctx fake, "CTX"
      assert.is_true ssl.alpn_configure_ssl fake, "SSL"
      assert.equals "h2,http/1.1", captured.list
      assert.equals 11, captured.size
      assert.equals 1, captured.options

    it "ne tente rien quand aucun symbole ALPN n'est présent", ->
      fake = {}
      assert.is_nil ssl.alpn_configure_ctx fake, "CTX"
      assert.is_false ssl.alpn_configure_ssl fake, "SSL"

    it "échec du contexte → nil, sans annonce objet implicite", ->
      fake = { wolfSSL_CTX_UseALPN: -> 0 }
      assert.is_nil ssl.alpn_configure_ctx fake, "CTX"
      assert.is_false ssl.alpn_configure_ssl fake, "SSL"

    it "annonce serveur au niveau objet exposée par ALPN_PROTOCOLS", ->
      assert.equals "h2,http/1.1", ssl.ALPN_PROTOCOLS

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
