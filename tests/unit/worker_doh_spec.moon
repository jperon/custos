-- tests/unit/worker_doh_spec.moon
-- Tests unitaires du worker DoH : fonctions pures de parsing HTTP/DNS.
-- La détection PRI (HTTP/2 sans ALPN) est couverte par le test E2E G12.

ffi = require "ffi"

-- Stubs minimaux pour charger worker_doh sans dépendances runtime.
package.loaded["config"] = package.loaded["config"] or {
  doh:     { enabled: true, port: 8443, upstream_ipv4: "1.1.1.3",
             upstream_ipv6: "", upstream_port: 53, upstream_timeout_ms: 2000,
             cert: nil, key: nil, prefer_ipv6: false }
  runtime: { log_level: "INFO", benchmark: false }
  nft:     { family: "bridge", ip_timeout: "5m" }
  filter:  { rules: {}, default_rules: {}, decision: {}, sources: {},
             nets: {}, macs: {}, times: {}, userlists: {}, users: {} }
  auth:    { port: 33443 }
  sni:     {}
}
log_errors = {}
package.loaded["log"] = {
  log_debug: (->), log_info: (->), log_warn: (->)
  log_error: (thunk) ->
    fields = if type(thunk) == "function" then thunk! else nil
    log_errors[#log_errors + 1] = fields
  debug: (->), info: (->), warn: (->), error: (->)
  rate_limited: (-> (->))
  set_action_prefix: (->)
}
-- Comportements injectables : les modules sont chargés une seule fois par
-- worker_doh (destructuration au require), donc les tests doivent passer par
-- ces tables d'indirection plutôt que réassigner package.loaded après coup.
mac_stub = { mac: nil, vlan: nil }
package.loaded["mac_learner_ipc"] = {
  get_mac:  (ip) -> mac_stub.mac
  get_vlan: (ip) -> mac_stub.vlan
}
package.loaded["doh.upstream"]    = {
  new_client: (ip, port, ms) -> {}, nil
  query:      (c, raw)        -> nil, "stub"
  close:      (c)             -> nil
  probe_ipv6: (ip, port)      -> false
}
query_stub = { process_query: (raw, ip, mac, up, vlan) -> nil, "stub" }
package.loaded["doh.query"]       = {
  process_query: (raw, ip, mac, up, vlan) -> query_stub.process_query raw, ip, mac, up, vlan
}
package.loaded["auth.cert_cache"] = {
  create_cache: (n, ttl) -> { set: (->), get: (-> nil), stats: (-> {size:0}) }
}
cert_stub = {
  load_static:          (k, c) -> nil, "stub"
  load_or_generate_sni: (ip, cache) -> nil, "stub"
}
package.loaded["auth.cert"]       = {
  load_static:          (k, c) -> cert_stub.load_static k, c
  load_or_generate_sni: (ip, cache) -> cert_stub.load_or_generate_sni ip, cache
}
ssl_stub = { wrap: (sock, ctx) -> nil, "stub" }
package.loaded["auth.ffi_wolfssl"] = {
  wrap: (sock, ctx) -> ssl_stub.wrap sock, ctx
}
package.loaded["lib.socket"]  = { tcp: (-> nil), tcp6: (-> nil), select: (-> {}, {}) }
package.loaded["lib.process"] = { fork_child: (-> 1) }
http_calls = {}
http_stub = {
  read_request:      (conn, opts) -> nil, "stub"
  send_response:     (conn, status, headers, body) -> nil
  apply_io_timeouts: (conn, timeout) -> nil
}
package.loaded["lib.http"]    = {
  read_request: (conn, opts) -> http_stub.read_request conn, opts
  send_response: (conn, status, headers, body) ->
    http_stub.send_response conn, status, headers, body
  apply_io_timeouts: (conn, timeout) -> http_stub.apply_io_timeouts conn, timeout
  send_all: (conn, data) ->
    sent = 0
    while sent < #data
      chunk = if sent == 0 then data else data\sub(sent + 1)
      n = conn\send chunk
      return nil, "send_timeout" unless n
      sent += (if n == true then #chunk else n)
    true
}

doh = require "worker_doh"

-- ── b64url_decode ─────────────────────────────────────────────────────────────

describe "worker_doh.b64url_decode", ->

  it "décode une chaîne base64url valide (requête DNS example.com A)", ->
    -- "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"
    raw = doh.b64url_decode "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"
    assert.is_not_nil raw
    assert.is_true #raw > 0, "doit retourner des octets"
    -- Les 2 premiers octets sont le transaction ID (0x0000 dans cet exemple)
    assert.equals 0, raw\byte 1
    assert.equals 0, raw\byte 2

  it "décode correctement sans padding (base64url standard)", ->
    -- "dGVzdA" = "test" en base64url (sans padding)
    result = doh.b64url_decode "dGVzdA"
    assert.equals "test", result

  it "retourne une chaîne vide si entrée vide", ->
    result = doh.b64url_decode ""
    assert.equals "", result

  it "tolère le padding explicite", ->
    result = doh.b64url_decode "dGVzdA=="
    assert.equals "test", result

-- ── query_param ──────────────────────────────────────────────────────────────

describe "worker_doh.query_param", ->

  it "extrait un paramètre simple", ->
    assert.equals "google.com", doh.query_param "/dns-query?name=google.com&type=A", "name"

  it "extrait le type", ->
    assert.equals "A", doh.query_param "/dns-query?name=google.com&type=A", "type"

  it "retourne nil si paramètre absent", ->
    assert.is_nil doh.query_param "/dns-query?name=google.com", "type"

  it "fonctionne avec le paramètre dns", ->
    assert.equals "AAABAAABAAAAAAAAA", doh.query_param "/dns-query?dns=AAABAAABAAAAAAAAA", "dns"

-- ── build_dns_query ──────────────────────────────────────────────────────────

describe "worker_doh.build_dns_query", ->

  it "construit une requête A valide", ->
    raw = doh.build_dns_query "example.com", 1  -- type A = 1
    assert.is_not_nil raw
    assert.is_true #raw >= 12, "header DNS = 12 octets minimum"
    -- Structure fin : QTYPE (2 octets) + QCLASS (2 octets)
    -- QTYPE A = 0x0001 : octet de poids fort = 0, poids faible = 1
    assert.equals 0, raw\byte(#raw - 3)
    assert.equals 1, raw\byte(#raw - 2)

  it "construit une requête AAAA valide", ->
    raw = doh.build_dns_query "example.com", 28  -- type AAAA = 28 = 0x001C
    assert.is_not_nil raw
    -- QTYPE AAAA = 0x001C
    assert.equals 0,  raw\byte(#raw - 3)
    assert.equals 28, raw\byte(#raw - 2)

  it "retourne nil pour un nom de domaine nil", ->
    raw = doh.build_dns_query nil, 1
    assert.is_nil raw

  it "retourne nil pour un nom de domaine vide", ->
    raw = doh.build_dns_query "", 1
    assert.is_nil raw

-- ── handshake_should_continue ────────────────────────────────────────────────

describe "worker_doh.handshake_should_continue", ->
  it "continue tant que le handshake n'est pas fini et dans l'échéance", ->
    assert.is_true doh.handshake_should_continue false, 0, 100, 115

  it "abandonne si l'échéance est dépassée", ->
    assert.is_false doh.handshake_should_continue false, 0, 116, 115

  it "abandonne si le handshake est terminé", ->
    assert.is_false doh.handshake_should_continue true, 0, 100, 115

  it "abandonne après 50 tentatives", ->
    assert.is_false doh.handshake_should_continue false, 50, 100, 115

-- ── handle_h2 : plafond cumulé des DATA ─────────────────────────────────────

-- Connexion factice : préface "SM\r\n\r\n" puis flux de frames brutes.
make_h2_conn = (raw) ->
  pos = 1
  line_idx = 0
  lines = { "SM", "" }
  sent = {}
  {
    receive: (mode) =>
      if mode == "*l"
        line_idx += 1
        return lines[line_idx]
      n = tonumber mode
      return nil, "eof" if pos > #raw
      chunk = raw\sub pos, pos + n - 1
      pos += #chunk
      chunk
    send: (data) =>
      sent[#sent + 1] = data
      #data
    _sent: -> table.concat sent
  }

h2_frame_raw = (ftype, flags, sid, payload) ->
  payload = payload or ""
  n = #payload
  string.char(
    bit.band(bit.rshift(n, 16), 0xFF),
    bit.band(bit.rshift(n,  8), 0xFF),
    bit.band(n,                 0xFF),
    ftype, flags,
    bit.band(bit.rshift(sid, 24), 0xFF),
    bit.band(bit.rshift(sid, 16), 0xFF),
    bit.band(bit.rshift(sid,  8), 0xFF),
    bit.band(sid,                 0xFF)
  ) .. payload

describe "worker_doh.handle_h2 — plafond DATA", ->
  bit = require "bit"

  it "rejette un cumul DATA supérieur à 65535 octets", ->
    frames = { h2_frame_raw 0x1, 0x4, 1, "" }
    for _ = 1, 4
      frames[#frames + 1] = h2_frame_raw 0x0, 0, 1, string.rep "x", 16384
    frames[#frames + 1] = h2_frame_raw 0x0, 0x1, 1, "y"
    conn = make_h2_conn table.concat frames
    resp, err = doh.handle_h2 conn, "1.2.3.4", nil, {}, nil
    assert.is_nil resp
    assert.equals "h2_data_too_large", err
    sent = conn._sent!
    expected_goaway = string.char(0,0,8, 0x7, 0, 0,0,0,0, 0,0,0,0,0,0,0,6)
    assert.equals expected_goaway, sent\sub -17

-- ── handle_h2 : limite connue (GET HEADERS+END_STREAM sans DATA) ────────────

describe "worker_doh.handle_h2 — GET HTTP/2 sans DATA", ->
  it "HEADERS avec END_STREAM sans DATA → h2_incomplete + GOAWAY", ->
    -- Limite connue : handle_h2 ne décode pas HPACK et ne termine le flux que
    -- sur une frame DATA avec END_STREAM. Un GET RFC 8484 (HEADERS +
    -- END_STREAM, sans DATA) est donc refusé avec GOAWAY.
    conn = make_h2_conn h2_frame_raw 0x1, 0x1, 1, ""
    resp, err = doh.handle_h2 conn, "1.2.3.4", nil, {}, nil
    assert.is_nil resp
    assert.equals "h2_incomplete", err
    sent = conn._sent!
    expected_goaway = string.char(0,0,8, 0x7, 0, 0,0,0,0, 0,0,0,0,0,0,0,1)
    assert.equals expected_goaway, sent\sub -17

-- ── Helpers JSON / DNS forgés ────────────────────────────────────────────────
-- Réponses DNS construites à la main (header + question example.com + RRs) pour
-- vérifier le JSON rendu par dns_response_json sans dépendre d'un résolveur.

sp_dns = require("ipparse.lib.pack_compat").pack
QCLASS_IN = 1
qname_example_dns = "\7example\3com\0"

make_dns_response = (rcode=0, answers={}) ->
  header = sp_dns ">H H H H H H", 0x1234, 0x8180 + rcode, 1, #answers, 0, 0
  question = qname_example_dns .. sp_dns ">H H", 1, QCLASS_IN
  rrs = {}
  for a in *answers
    rrs[#rrs + 1] = "\192\012" .. sp_dns ">H H I4 s2", a.rtype, QCLASS_IN, a.ttl or 60, a.rdata
  header .. question .. table.concat rrs

describe "worker_doh — helpers JSON", ->

  it "json_escape échappe backslash, guillemets et caractères de contrôle", ->
    assert.equals "a\\\\b", doh.json_escape "a\\b"
    assert.equals "a\\\"b", doh.json_escape "a\"b"
    assert.equals "a\\nb\\rc\\td", doh.json_escape "a\nb\rc\td"

  it "json_escape convertit en chaîne et rend une chaîne vide pour nil", ->
    assert.equals "", doh.json_escape nil
    assert.equals "42", doh.json_escape 42

  it "json_quote entoure et échappe", ->
    assert.equals "\"a\\\"b\"", doh.json_quote "a\"b"

  it "qtype_from_name accepte le nom, la casse, le nombre et retombe sur A", ->
    assert.equals 1,  doh.qtype_from_name "A"
    assert.equals 28, doh.qtype_from_name "aaaa"
    assert.equals 28, doh.qtype_from_name "28"
    assert.equals 1,  doh.qtype_from_name nil
    assert.equals 1,  doh.qtype_from_name "TYPE_INCONNU"

  it "url_decode décode %xx et le + de formulaire", ->
    assert.equals "a b c", doh.url_decode "a%20b+c"
    assert.equals "", doh.url_decode nil
    -- Séquence invalide laissée telle quelle (gsub sans correspondance).
    assert.equals "a%zzb", doh.url_decode "a%zzb"

  it "query_param décode les valeurs percent-encoded", ->
    assert.equals "ex.ample com", doh.query_param "/dns-query?name=ex%2Eample%20com", "name"

  it "encode_qname produit les labels longueur+contenu et le zéro final", ->
    assert.equals "\7example\3com\0", doh.encode_qname "example.com"
    assert.equals "\7example\3com\0", doh.encode_qname "example.com."
    assert.is_nil doh.encode_qname ""
    assert.is_nil doh.encode_qname nil

  it "encode_qname rejette un label de plus de 63 octets", ->
    label = string.rep "a", 64
    assert.is_nil doh.encode_qname "#{label}.com"
    assert.is_nil doh.build_dns_query "#{label}.com", 1

describe "worker_doh — rr_data_json", ->

  it "rend une adresse IPv4 en notation pointée", ->
    assert.equals "1.2.3.4", doh.rr_data_json { rtype: 1, rdata: string.char(1,2,3,4) }

  it "rend une adresse IPv6 en groupes hexadécimaux", ->
    rdata = string.char(0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
    assert.equals "2001:db8:0:0:0:0:0:1", doh.rr_data_json { rtype: 28, rdata: rdata }

  it "rend les données brutes pour un autre type ou une taille inattendue", ->
    assert.equals "cname.example", doh.rr_data_json { rtype: 5, rdata: "cname.example" }
    assert.equals "\1\2\3", doh.rr_data_json { rtype: 1, rdata: "\1\2\3" }

describe "worker_doh — dns_response_json", ->

  it "rend une réponse A complète (Status 0, question, answer)", ->
    raw = make_dns_response 0, { { rtype: 1, ttl: 60, rdata: string.char(1,2,3,4) } }
    json = doh.dns_response_json raw
    assert.truthy json\find '"Status":0', 1, true
    assert.truthy json\find '"TC":false', 1, true
    assert.truthy json\find '"RD":true', 1, true
    assert.truthy json\find '"RA":true', 1, true
    assert.truthy json\find '"Question":[{"name":"example.com","type":1}]', 1, true
    assert.truthy json\find '"Answer":[{"name":"example.com","type":1,"TTL":60,"data":"1.2.3.4"}]', 1, true

  it "rend une réponse AAAA", ->
    rdata = string.char(0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
    raw = make_dns_response 0, { { rtype: 28, ttl: 300, rdata: rdata } }
    json = doh.dns_response_json raw
    assert.truthy json\find '"type":28', 1, true
    assert.truthy json\find '"data":"2001:db8:0:0:0:0:0:1"', 1, true

  it "rend NXDOMAIN avec Status 3 et aucune answer", ->
    raw = make_dns_response 3, {}
    json = doh.dns_response_json raw
    assert.truthy json\find '"Status":3', 1, true
    assert.truthy json\find '"Answer":[]', 1, true

  it "ignore les RR d'un type non A/AAAA (CNAME) dans Answer", ->
    raw = make_dns_response 0, { { rtype: 5, rdata: "cname.example" } }
    json = doh.dns_response_json raw
    assert.truthy json\find '"Answer":[]', 1, true

  it "rend nil pour des octets DNS invalides", ->
    assert.is_nil doh.dns_response_json "pas du DNS"

-- ── handle_doh_client : routage HTTP/1.1 et statuts ─────────────────────────

make_client_stub = (local_ip="192.0.2.10") ->
  closed = false
  {
    getsockname: -> local_ip
    settimeout: (t) -> nil
    close: -> closed = true
    _closed: -> closed
  }

make_tls_stub = (opts={}) ->
  sent = {}
  closed = false
  handshake_result = if opts.handshake_result == nil then true else opts.handshake_result
  handshake_err = opts.handshake_err
  {
    dohandshake: -> handshake_result, handshake_err
    selected_alpn: -> opts.alpn
    receive: (mode) -> nil, "unused"
    send: (data) -> sent[#sent + 1] = data; #data
    close: -> closed = true
    _sent: -> table.concat sent
    _closed: -> closed
  }

describe "worker_doh.handle_doh_client — routage HTTP/1.1", ->

  capture = {}
  before_each ->
    capture = { sent: {}, processed: {}, read_opts: nil, io_timeout: nil }
    log_errors = {}
    cert_stub.load_static = (k, c) -> { ctx: true }
    ssl_stub.wrap = (sock, ctx) -> make_tls_stub {}
    query_stub.process_query = (raw, ip, mac, up, vlan) ->
      capture.processed[#capture.processed + 1] = { :raw, :ip, :mac, :up, :vlan }
      "RESP_BYTES", nil
    http_stub.read_request = (conn, opts) ->
      capture.read_opts = opts
      capture.req
    http_stub.send_response = (conn, status, headers, body) ->
      capture.sent[#capture.sent + 1] = { :status, :headers, :body }
      nil
    http_stub.apply_io_timeouts = (conn, timeout) -> capture.io_timeout = timeout

  run_client = (req, opts={}) ->
    capture.req = req
    tls = opts.tls or make_tls_stub {}
    ssl_stub.wrap = (sock, ctx) -> tls
    args = {
      client: make_client_stub!
      peer_ip: "192.0.2.10"
      state: {
        static_cert_paths: { key: "k", cert: "c" }
        cert_cache: {}
        client_timeout: opts.client_timeout or 7
        upstream: { marker: true }
      }
    }
    doh.handle_doh_client args
    if #log_errors > 0
      err = log_errors[1] and log_errors[1].err
      error "handle_doh_client a journalisé une erreur : #{tostring err}"
    tls

  it "GET ?dns= décode le base64url et rend 200 application/dns-message", ->
    b64 = "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"
    expected = doh.b64url_decode b64
    tls = run_client { method: "GET", path: "/dns-query?dns=#{b64}", headers: {}, body: "" }
    assert.equals 1, #capture.processed
    assert.equals expected, capture.processed[1].raw
    assert.equals "192.0.2.10", capture.processed[1].ip
    assert.equals 1, #capture.sent
    assert.equals 200, capture.sent[1].status
    assert.equals "application/dns-message", capture.sent[1].headers["Content-Type"]
    assert.equals "RESP_BYTES", capture.sent[1].body
    assert.is_true tls._closed!

  it "POST application/dns-message transmet le corps brut et rend 200", ->
    body = "\0\1\2\3"
    tls = run_client {
      method: "POST", path: "/dns-query"
      headers: { ["content-type"]: "application/dns-message" }
      body: body
    }
    assert.equals body, capture.processed[1].raw
    assert.equals 200, capture.sent[1].status
    assert.equals "application/dns-message", capture.sent[1].headers["Content-Type"]
    assert.equals "RESP_BYTES", capture.sent[1].body
    assert.is_true tls._closed!

  it "GET JSON construit la requête demandée et rend le JSON DNS", ->
    forged_resp = make_dns_response 0, { { rtype: 1, ttl: 60, rdata: string.char(1,2,3,4) } }
    query_stub.process_query = (raw) ->
      capture.processed[#capture.processed + 1] = { :raw }
      forged_resp, nil
    run_client {
      method: "GET", path: "/dns-query?name=example.com&type=AAAA"
      headers: { accept: "application/dns-json" }
      body: ""
    }
    raw = capture.processed[1].raw
    -- QTYPE AAAA (28) en fin de question, avant QCLASS.
    assert.equals 28, raw\byte(#raw - 2)
    assert.equals 200, capture.sent[1].status
    assert.equals "application/dns-json", capture.sent[1].headers["Content-Type"]
    assert.truthy capture.sent[1].body\find '"Status":0', 1, true
    assert.truthy capture.sent[1].body\find '"data":"1.2.3.4"', 1, true

  it "POST avec un content-type non DNS rend 415 sans interroger l'amont", ->
    run_client {
      method: "POST", path: "/dns-query"
      headers: { ["content-type"]: "text/plain" }
      body: "x"
    }
    assert.equals 415, capture.sent[1].status
    assert.equals "Unsupported Media Type", capture.sent[1].body
    assert.equals 0, #capture.processed

  it "GET sans paramètre dns ni JSON rend 400 Bad Request", ->
    run_client { method: "GET", path: "/dns-query", headers: {}, body: "" }
    assert.equals 400, capture.sent[1].status
    assert.equals "Bad Request", capture.sent[1].body
    assert.equals 0, #capture.processed

  it "chemin inconnu rend 400 Bad Request", ->
    run_client { method: "GET", path: "/autre", headers: {}, body: "" }
    assert.equals 400, capture.sent[1].status
    assert.equals "Bad Request", capture.sent[1].body

  it "corps annoncé trop gros (read_request) rend 413 Payload Too Large", ->
    http_stub.read_request = (conn, opts) ->
      capture.read_opts = opts
      nil, "body_too_large"
    run_client { method: "POST", path: "/dns-query", headers: {}, body: "" }
    assert.equals 413, capture.sent[1].status
    assert.equals "Payload Too Large", capture.sent[1].body
    assert.equals 0, #capture.processed

  it "échec de process_query rend 502 Bad Gateway", ->
    query_stub.process_query = -> nil, "amont muet"
    run_client {
      method: "POST", path: "/dns-query"
      headers: { ["content-type"]: "application/dns-message" }
      body: "\0\1"
    }
    assert.equals 502, capture.sent[1].status
    assert.equals "Bad Gateway", capture.sent[1].body

  it "transmet le timeout client et le plafond de corps à read_request", ->
    run_client { method: "GET", path: "/dns-query?dns=AAAB", headers: {}, body: "" }, { client_timeout: 9 }
    assert.equals 9, capture.read_opts.timeout
    assert.equals 65535, capture.read_opts.max_body
    assert.equals 9, capture.io_timeout

  it "handshake TLS fatal : ferme la connexion sans lire de requête", ->
    tls = make_tls_stub { handshake_result: false, handshake_err: "peer_closed" }
    run_client { method: "GET", path: "/dns-query", headers: {}, body: "" }, { :tls }
    assert.is_nil capture.read_opts
    assert.equals 0, #capture.sent
    assert.is_true tls._closed!

-- ── handle_h2 : frame annoncée trop grande (B4) ─────────────────────────────

describe "worker_doh.handle_h2 — frame trop longue", ->
  bit = require "bit"

  it "rejette une frame de 0xFFFFFF octets sans lire le payload et renvoie GOAWAY", ->
    -- En-tête seul : longueur 0xFFFFFF annoncée, aucun octet de corps fourni.
    header = string.char(0xFF, 0xFF, 0xFF, 0x0, 0, 1, 0, 0, 1)
    conn = make_h2_conn header
    resp, err = doh.handle_h2 conn, "1.2.3.4", nil, {}, nil
    assert.is_nil resp
    assert.equals "h2_frame_too_large", err
    sent = conn._sent!
    expected_goaway = string.char(0,0,8, 0x7, 0, 0,0,0,0, 0,0,0,0,0,0,0,6)
    assert.equals expected_goaway, sent\sub -17
