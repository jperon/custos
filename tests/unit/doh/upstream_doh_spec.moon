-- tests/unit/doh/upstream_doh_spec.moon
-- Tests unitaires de doh.upstream_doh (new_client, query, close).
-- lib.socket et auth.ffi_wolfssl sont stubbés pour éviter toute I/O réseau.

sp = require("ipparse.lib.pack_compat").pack

eval_log = (f) -> (type(f) == "function") and f!
package.loaded["log"] = {
  log_warn: eval_log, log_debug: eval_log, log_info: eval_log
}

-- Simule une réponse HTTP/1.1 complète encapsulant des octets DNS arbitraires.
make_http_resp = (body, status=200) ->
  reason = if status == 200 then "OK" else "Error"
  "HTTP/1.1 #{status} #{reason}\r\nContent-Type: application/dns-message\r\nContent-Length: #{#body}\r\n\r\n" .. body

-- Fabrication d'un stub TLS minimaliste.
make_tls_stub = (recv_data, send_ok=true) ->
  sent_data = nil
  received  = false
  {
    doconnect: -> true
    send: (data) =>
      sent_data = data
      return nil unless send_ok
      #data
    receive: (sz) =>
      if received
        return nil, "eof_from_peer"
      received = true
      recv_data
    close: (->)
    closed: false
    _sent: -> sent_data
  }

-- Fabrication du stub ssl (auth.ffi_wolfssl).
make_ssl_stub = (tls_stub) ->
  {
    newclient_context: (opts) -> { ctx: "stub_ctx", closed: false }
    wrap: (sock, ctx)       -> tls_stub
    free_context: (->)
  }

-- Fabrication du stub socket (lib.socket).
make_socket_stub = (connect_ok=true) ->
  sock = {
    fd: 42
    closed: false
    connect: (host, port) =>
      error "connect_refused" unless connect_ok
    close: => @closed = true
  }
  mod = {
    create_tcp:  -> sock
    create_tcp6: -> sock
    C: {
      setsockopt: (fd, ...) -> 0
    }
    SOL_SOCKET:  1
    SO_RCVTIMEO: 20
    SO_SNDTIMEO: 21
    _sock: -> sock
  }
  mod

-- Charge upstream_doh en injectant les stubs dans package.loaded.
load_mod = (tls_stub, connect_ok=true) ->
  ssl_stub    = make_ssl_stub tls_stub
  socket_stub = make_socket_stub connect_ok
  package.loaded["auth.ffi_wolfssl"] = ssl_stub
  package.loaded["lib.socket"]       = socket_stub
  package.loaded["doh.upstream_doh"] = nil
  require "doh.upstream_doh"

-- Réponse DNS NOERROR minimale (12 octets d'en-tête)
dns_resp = sp(">H H H H H H", 0x1234, 0x8180, 1, 1, 0, 0)

describe "doh.upstream_doh", ->

  describe "new_client", ->

    it "URL valide → handle avec _mod", ->
      mod = load_mod make_tls_stub make_http_resp(dns_resp)
      h, err = mod.new_client "https://1.1.1.1/dns-query"
      assert.is_nil err
      assert.is_not_nil h
      assert.equals h._mod, mod

    it "URL sans chemin → /dns-query par défaut", ->
      mod = load_mod make_tls_stub make_http_resp(dns_resp)
      h = mod.new_client "https://1.1.1.1"
      assert.is_not_nil h
      assert.equals "/dns-query", h.path

    it "URL avec port personnalisé", ->
      mod = load_mod make_tls_stub make_http_resp(dns_resp)
      h = mod.new_client "https://9.9.9.9:5353/dns-query"
      assert.is_not_nil h
      assert.equals "9.9.9.9", h.host

    it "URL avec hostname → résolution et connexion (pas d'inet_pton)", ->
      -- Régression : new_client échouait avec "inet_pton failed" si l'URL
      -- contient un nom d'hôte au lieu d'une IP littérale.
      -- getaddrinfo (via libc = ffi.C) doit résoudre "localhost".
      mod = load_mod make_tls_stub make_http_resp(dns_resp)
      h, err = mod.new_client "https://localhost/dns-query"
      -- La résolution réussit ; l'erreur éventuelle doit être connect_failed
      -- (socket vers localhost:443) et NON pas "inet_pton failed".
      if err
        assert.falsy err\find "inet_pton", 1, true
      else
        assert.is_not_nil h

    it "URL invalide → nil + erreur", ->
      mod = load_mod make_tls_stub make_http_resp(dns_resp)
      h, err = mod.new_client "http://not-https.example/"
      assert.is_nil h
      assert.is_not_nil err

    it "connect échoué → nil + erreur", ->
      mod = load_mod (make_tls_stub make_http_resp dns_resp), false
      h, err = mod.new_client "https://1.1.1.1/dns-query"
      assert.is_nil h
      assert.truthy err\find "connect_failed"

  describe "query", ->

    it "réponse 200 → retourne le corps DNS", ->
      tls = make_tls_stub make_http_resp(dns_resp)
      mod = load_mod tls
      h   = mod.new_client "https://1.1.1.1/dns-query"
      body, err = mod.query h, "dns_raw_query"
      assert.is_nil err
      assert.equals dns_resp, body

    it "envoie bien un POST /dns-query avec Content-Type dns-message", ->
      tls = make_tls_stub make_http_resp(dns_resp)
      mod = load_mod tls
      h   = mod.new_client "https://1.1.1.1/dns-query"
      mod.query h, "dns_raw_query"
      sent = tls._sent!
      assert.truthy sent\find "POST /dns%-query"
      assert.truthy sent\find "Content%-Type: application/dns%-message"
      assert.truthy sent\find "Accept: application/dns%-message"
      assert.truthy sent\find "dns_raw_query"

    it "réponse HTTP 503 → nil + erreur http_status", ->
      tls = make_tls_stub make_http_resp(dns_resp, 503)
      mod = load_mod tls
      h   = mod.new_client "https://1.1.1.1/dns-query"
      body, err = mod.query h, "dns_raw_query"
      assert.is_nil body
      assert.truthy err\find "503"

    it "réponse vide → nil + erreur", ->
      tls = make_tls_stub ""
      mod = load_mod tls
      h   = mod.new_client "https://1.1.1.1/dns-query"
      body, err = mod.query h, "dns_raw_query"
      assert.is_nil body
      assert.is_not_nil err

  describe "close", ->

    it "ferme la connexion TLS", ->
      closed = false
      tls = make_tls_stub make_http_resp(dns_resp)
      tls.close = -> closed = true
      mod = load_mod tls
      h   = mod.new_client "https://1.1.1.1/dns-query"
      mod.close h
      assert.is_true closed

    it "close sur nil est sans effet", ->
      mod = load_mod make_tls_stub make_http_resp(dns_resp)
      assert.has_no_error -> mod.close nil
