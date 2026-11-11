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

-- Requête/réponse DNS minimales (12 octets) corrélées par txid.
make_dns_req = (txid=0x1234) ->
  sp ">H H H H H H", txid, 0x0100, 1, 0, 0, 0
make_dns_resp = (txid=0x1234) ->
  sp ">H H H H H H", txid, 0x8180, 1, 1, 0, 0
dns_req  = make_dns_req 0x1234
dns_resp = make_dns_resp 0x1234

-- Fabrication d'un stub TLS minimaliste. `send_chunk` simule des écritures
-- partielles (n < #data).
make_tls_stub = (recv_data, send_ok=true, send_chunk=nil) ->
  sent_data = ""
  received  = false
  {
    doconnect: -> true
    send: (data) =>
      return nil unless send_ok
      n = send_chunk and math.min(send_chunk, #data) or #data
      sent_data = sent_data .. data\sub(1, n)
      n
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
last_ssl_stub = nil
make_ssl_stub = (tls_stub, verify_ok=true, verify_why=nil, ca="/etc/ssl/certs/ca-certificates.crt") ->
  seen = { verif_calls: 0, ctx_opts: nil, wrap_opts: nil }
  stub = {
    verification_available: (opts) ->
      seen.verif_calls += 1
      return false, verify_why or "vérification indisponible", nil unless verify_ok
      true, nil, ca
    newclient_context: (opts) ->
      seen.ctx_opts = opts
      { ctx: "stub_ctx", closed: false, verify_peer: opts.verify_peer, ca_file: opts.ca_file }
    wrap: (sock, ctx, opts) ->
      seen.wrap_opts = opts
      tls_stub
    free_context: (->)
    _seen: -> seen
  }
  last_ssl_stub = stub
  stub

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
load_mod = (tls_stub, connect_ok=true, verify_ok=true, verify_why=nil) ->
  ssl_stub    = make_ssl_stub tls_stub, verify_ok, verify_why
  socket_stub = make_socket_stub connect_ok
  package.loaded["auth.ffi_wolfssl"] = ssl_stub
  package.loaded["lib.socket"]       = socket_stub
  package.loaded["doh.upstream_doh"] = nil
  require "doh.upstream_doh"

-- Réponse DNS NOERROR minimale (12 octets d'en-tête) : dns_resp ci-dessus.

describe "doh.upstream_doh", ->

  describe "parse_url", ->

    it "IPv6 littéral sans port → crochets retirés", ->
      mod = load_mod make_tls_stub make_http_resp(dns_resp)
      r = { mod.parse_url "https://[2606:4700:4700::1111]/dns-query" }
      assert.same { "2606:4700:4700::1111", 443, "/dns-query" }, r

    it "IPv6 littéral avec port et chemin", ->
      mod = load_mod make_tls_stub make_http_resp(dns_resp)
      r = { mod.parse_url "https://[::1]:8443/dns-query" }
      assert.same { "::1", 8443, "/dns-query" }, r

    it "IPv6 littéral avec port sans chemin → /dns-query", ->
      mod = load_mod make_tls_stub make_http_resp(dns_resp)
      r = { mod.parse_url "https://[::1]:8443" }
      assert.same { "::1", 8443, "/dns-query" }, r

    it "IPv4 avec port sans chemin → /dns-query", ->
      mod = load_mod make_tls_stub make_http_resp(dns_resp)
      r = { mod.parse_url "https://9.9.9.9:5353" }
      assert.same { "9.9.9.9", 5353, "/dns-query" }, r

    it "nom d'hôte sans chemin → /dns-query", ->
      mod = load_mod make_tls_stub make_http_resp(dns_resp)
      r = { mod.parse_url "https://dns.example.org" }
      assert.same { "dns.example.org", 443, "/dns-query" }, r

    it "URL non https → nil", ->
      mod = load_mod make_tls_stub make_http_resp(dns_resp)
      r = { mod.parse_url "http://1.1.1.1/dns-query" }
      assert.same { nil, nil, nil }, r

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

    it "IPv6 littéral → hôte sans crochets, Host header entre crochets", ->
      mod = load_mod make_tls_stub make_http_resp(dns_resp)
      h, err = mod.new_client "https://[::1]:8443/dns-query"
      assert.is_nil err
      assert.equals "::1", h.host
      assert.equals 8443, h.port
      assert.equals "[::1]:8443", h.host_header

    it "port non standard sans chemin → port conservé", ->
      mod = load_mod make_tls_stub make_http_resp(dns_resp)
      h = mod.new_client "https://9.9.9.9:5353"
      assert.equals 5353, h.port
      assert.equals "/dns-query", h.path

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

  describe "vérification TLS du repli", ->

    it "verify_tls=true → verify_peer + magasin de CA + SNI + contrôle du nom", ->
      mod = load_mod make_tls_stub(make_http_resp dns_resp)
      h, err = mod.new_client "https://localhost/dns-query", 2000, true
      assert.is_nil err
      assert.is_not_nil h
      seen = last_ssl_stub._seen!
      assert.equals 1, seen.verif_calls
      assert.is_true seen.ctx_opts.verify_peer
      assert.equals "/etc/ssl/certs/ca-certificates.crt", seen.ctx_opts.ca_file
      assert.equals "localhost", seen.wrap_opts.sni
      assert.equals "localhost", seen.wrap_opts.check_domain

    it "IP littérale → pas de SNI (RFC 6066) mais contrôle du nom", ->
      mod = load_mod make_tls_stub(make_http_resp dns_resp)
      h, err = mod.new_client "https://1.1.1.1/dns-query", 2000, true
      assert.is_nil err
      seen = last_ssl_stub._seen!
      assert.is_nil seen.wrap_opts.sni
      assert.equals "1.1.1.1", seen.wrap_opts.check_domain

    it "vérification impossible → nil + tls_verify_unavailable (jamais silencieux)", ->
      mod = load_mod make_tls_stub(make_http_resp dns_resp), true, false,
        "symboles absents: wolfSSL_check_domain_name"
      h, err = mod.new_client "https://1.1.1.1/dns-query", 2000, true
      assert.is_nil h
      assert.truthy err\find "tls_verify_unavailable", 1, true
      assert.truthy err\find "wolfSSL_check_domain_name", 1, true

    it "verify_tls=false → aucune sonde, aucun contrôle du nom", ->
      mod = load_mod make_tls_stub(make_http_resp dns_resp)
      h, err = mod.new_client "https://1.1.1.1/dns-query", 2000, false
      assert.is_nil err
      seen = last_ssl_stub._seen!
      assert.equals 0, seen.verif_calls
      assert.is_nil seen.wrap_opts.check_domain

  describe "query", ->

    it "réponse 200 → retourne le corps DNS", ->
      tls = make_tls_stub make_http_resp(dns_resp)
      mod = load_mod tls
      h   = mod.new_client "https://1.1.1.1/dns-query"
      body, err = mod.query h, dns_req
      assert.is_nil err
      assert.equals dns_resp, body

    it "envoie bien un POST /dns-query avec Content-Type dns-message", ->
      tls = make_tls_stub make_http_resp(dns_resp)
      mod = load_mod tls
      h   = mod.new_client "https://1.1.1.1/dns-query"
      mod.query h, dns_req
      sent = tls._sent!
      assert.truthy sent\find "POST /dns%-query"
      assert.truthy sent\find "Content%-Type: application/dns%-message"
      assert.truthy sent\find "Accept: application/dns%-message"
      assert.truthy sent\find dns_req, 1, true

    it "écritures partielles → la requête complète est envoyée", ->
      tls = make_tls_stub make_http_resp(dns_resp), true, 3
      mod = load_mod tls
      h   = mod.new_client "https://1.1.1.1/dns-query"
      body, err = mod.query h, dns_req
      assert.is_nil err
      assert.equals dns_resp, body
      sent = tls._sent!
      assert.truthy sent\find "POST /dns%-query"
      assert.truthy sent\find dns_req, 1, true

    it "écriture impossible (WANT_WRITE persistant) → send_failed borné", ->
      tls = make_tls_stub make_http_resp(dns_resp), false
      mod = load_mod tls
      h   = mod.new_client "https://1.1.1.1/dns-query"
      body, err = mod.query h, dns_req
      assert.is_nil body
      assert.truthy err\find "send_failed", 1, true

    it "Content-Length énorme (> 65535) → rejet avant lecture", ->
      hostile = "HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n" .. dns_resp
      tls = make_tls_stub hostile
      mod = load_mod tls
      h   = mod.new_client "https://1.1.1.1/dns-query"
      body, err = mod.query h, dns_req
      assert.is_nil body
      assert.truthy err\find "content_length_too_large", 1, true

    it "statut 500 → nil + erreur http_status", ->
      tls = make_tls_stub make_http_resp(dns_resp, 500)
      mod = load_mod tls
      h   = mod.new_client "https://1.1.1.1/dns-query"
      body, err = mod.query h, dns_req
      assert.is_nil body
      assert.truthy err\find "http_status_500", 1, true

    it "corps tronqué (Content-Length > reçu) → nil + truncated_body", ->
      hostile = "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n" .. dns_resp
      tls = make_tls_stub hostile
      mod = load_mod tls
      h   = mod.new_client "https://1.1.1.1/dns-query"
      body, err = mod.query h, dns_req
      assert.is_nil body
      assert.truthy err\find "truncated_body", 1, true

    it "txid de réponse différent de la requête → nil + txid_mismatch", ->
      tls = make_tls_stub make_http_resp(make_dns_resp 0x9999)
      mod = load_mod tls
      h   = mod.new_client "https://1.1.1.1/dns-query"
      body, err = mod.query h, dns_req
      assert.is_nil body
      assert.truthy err\find "txid_mismatch", 1, true

    it "réponse HTTP 503 → nil + erreur http_status", ->
      tls = make_tls_stub make_http_resp(dns_resp, 503)
      mod = load_mod tls
      h   = mod.new_client "https://1.1.1.1/dns-query"
      body, err = mod.query h, dns_req
      assert.is_nil body
      assert.truthy err\find "503"

    it "réponse vide → nil + erreur", ->
      tls = make_tls_stub ""
      mod = load_mod tls
      h   = mod.new_client "https://1.1.1.1/dns-query"
      body, err = mod.query h, dns_req
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
