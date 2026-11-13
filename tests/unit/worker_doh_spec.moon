-- tests/unit/worker_doh_spec.moon
-- Tests unitaires du worker DoH : fonctions pures de parsing HTTP/DNS.
-- La détection PRI (HTTP/2 sans ALPN) est couverte par le test E2E G12.

ffi = require "ffi"
bit = require "bit"
hpack = require "doh.hpack"

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
log_records = {}
-- Les stubs de log évaluent les thunks (comme le vrai log quand le niveau est
-- actif) : les corps des closures de journalisation sont ainsi exécutés et
-- couvrables, et les tests peuvent affirmer sur les champs journalisés.
eval_fields = (thunk) ->
  fields = if type(thunk) == "function" then thunk! else thunk
  log_records[#log_records + 1] = fields if type(fields) == "table"
  fields
package.loaded["log"] = {
  log_debug: (thunk) -> eval_fields thunk
  log_info:  (thunk) -> eval_fields thunk
  log_warn:  (thunk) -> eval_fields thunk
  log_error: (thunk) ->
    fields = if type(thunk) == "function" then thunk! else nil
    log_errors[#log_errors + 1] = fields
    log_records[#log_records + 1] = fields if type(fields) == "table"
  debug: (->), info: (->), warn: (->), error: (->)
  rate_limited: (-> (->))
  set_action_prefix: (->)
}
--- Réinitialise les deux journaux (erreurs + enregistrements).
reset_logs = ->
  log_errors = {}
  log_records = {}
--- Présence d'un enregistrement portant l'action donnée.
has_record = (action) ->
  for r in *log_records
    return true if type(r) == "table" and r.action == action
  false
--- Premier enregistrement portant l'action donnée, ou nil.
get_record = (action) ->
  for r in *log_records
    return r if type(r) == "table" and r.action == action
  nil
--- Actions journalisées, concaténées (diagnostic d'assertion).
record_actions = ->
  parts = {}
  for r in *log_records
    parts[#parts + 1] = type(r) == "table" and tostring(r.action) or tostring(r)
  table.concat parts, ","
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
-- Enregistrements des décisions nft transmises à doh.query par `run`.
captive_sets = {}
wildcard_meta = nil
package.loaded["doh.query"]       = {
  process_query: (raw, ip, mac, up, vlan) -> query_stub.process_query raw, ip, mac, up, vlan
  set_wildcard_rules: (meta) -> wildcard_meta = meta
  set_captive: (domain, ip4, ip6) ->
    captive_sets[#captive_sets + 1] = { :domain, :ip4, :ip6 }
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
  ALPN_PROTOCOLS: "h2,http/1.1"
}
-- lib.socket : table nommée, car worker_doh la capture au require — les tests
-- `run`/`make_server*` reconfigurent tcp/tcp6/select par indirection.
socket_stub = { tcp: (-> nil), tcp6: (-> nil), select: (-> {}, {}) }
package.loaded["lib.socket"]  = socket_stub
-- reap_one DOIT exister au require (destructuration) : les tests `run` s'arrêtent
-- sur l'entrée de boucle (reap_one → nil → break) sans jamais accepter ni forker.
process_stub = { fork_child: (-> 1), reap_one: (-> nil) }
package.loaded["lib.process"] = process_stub
-- upstream_select : capté par worker_doh au require. Stubbé le temps du chargement
-- puis restauré (les autres specs ont besoin du module réel) ; les tests `run`
-- pilotent les résultats via upstream_select_result/err (déclarés AVANT le
-- tableau pour être capturés comme locals et non comme globales).
upstream_select_result = nil
upstream_select_err = "stub"
upstream_select_stub = {
  select: (opts) -> upstream_select_result, upstream_select_err
}
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

saved_upstream_select = package.loaded["doh.upstream_select"]
package.loaded["doh.upstream_select"] = upstream_select_stub
doh = require "worker_doh"
-- Restaure immédiatement : seul worker_doh garde la référence au stub.
package.loaded["doh.upstream_select"] = saved_upstream_select

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
-- opts.fail_after : après N envois réussis, `send` échoue (nil, "send_timeout")
-- pour exercer les branches d'erreur d'écriture de handle_h2.
make_h2_conn = (raw, opts={}) ->
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
      if opts.fail_after and #sent >= opts.fail_after
        return nil, "send_timeout"
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

--- Découpe un flux de frames HTTP/2 serveur en {ftype, flags, sid, payload}.
h2_parse_frames = (raw) ->
  frames = {}
  pos = 1
  while pos + 8 <= #raw
    len = raw\byte(pos) * 65536 + raw\byte(pos + 1) * 256 + raw\byte(pos + 2)
    ftype = raw\byte pos + 3
    flags = raw\byte pos + 4
    sid = bit.band(bit.bor(
      bit.lshift(raw\byte(pos + 5), 24),
      bit.lshift(raw\byte(pos + 6), 16),
      bit.lshift(raw\byte(pos + 7), 8),
      raw\byte(pos + 8)
    ), 0x7FFFFFFF)
    payload = raw\sub pos + 9, pos + 8 + len
    frames[#frames + 1] = { ftype, flags, sid, payload }
    pos += 9 + len
  frames

--- Décode le premier bloc HEADERS d'un flux serveur.
h2_response_headers = (sent) ->
  headers = nil
  for f in *h2_parse_frames sent
    if f[1] == 0x1 and not headers
      headers, err = hpack.decode hpack.new_decoder!, f[4]
      assert.is_nil err
  headers

--- Décode le :status du premier bloc HEADERS d'un flux serveur.
h2_response_status = (sent) ->
  hpack.header_value h2_response_headers(sent), ":status"

--- Concatène les payloads DATA d'un flux serveur.
h2_response_body = (sent) ->
  parts = {}
  for f in *h2_parse_frames sent
    parts[#parts + 1] = f[4] if f[1] == 0x0
  table.concat parts

--- Construit une frame HEADERS avec un bloc HPACK minimal.
h2_headers_frame = (sid, headers, end_stream=false) ->
  flags = 0x4
  flags = bit.bor flags, 0x1 if end_stream
  h2_frame_raw 0x1, flags, sid, hpack.encode headers

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

-- ── handle_h2 : routage par pseudo-en-têtes HPACK ───────────────────────────

describe "worker_doh.handle_h2 — routage HPACK", ->

  capture = {}
  doh_query_b64 = "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"

  before_each ->
    capture = { processed: {}, resp: "DNS_RESPONSE" }
    query_stub.process_query = (raw, ip, mac, up, vlan) ->
      capture.processed[#capture.processed + 1] = { :raw, :ip, :mac, :up, :vlan }
      capture.resp, nil

  h2_run = (frames) ->
    conn = make_h2_conn frames
    resp, err = doh.handle_h2 conn, "1.2.3.4", nil, {}, nil
    { :resp, :err, sent: conn._sent! }

  it "GET RFC 8484 (HEADERS + END_STREAM, sans DATA) est traité", ->
    path = "/dns-query?dns=#{doh_query_b64}"
    frame = h2_headers_frame 1, {
      { ":method", "GET" }
      { ":scheme", "https" }
      { ":path", path }
      { ":authority", "1.2.3.4" }
    }, true
    r = h2_run frame
    assert.is_nil r.err
    assert.equals "DNS_RESPONSE", r.resp
    assert.equals 1, #capture.processed
    assert.equals doh.b64url_decode(doh_query_b64), capture.processed[1].raw
    assert.equals "200", h2_response_status r.sent

  it "POST application/dns-message sur /dns-query traite le corps DATA", ->
    body = "\0\1\2\3"
    headers = h2_headers_frame 1, {
      { ":method", "POST" }
      { ":scheme", "https" }
      { ":path", "/dns-query" }
      { ":authority", "1.2.3.4" }
      { "content-type", "application/dns-message" }
    }
    data = h2_frame_raw 0x0, 0x1, 1, body
    r = h2_run headers .. data
    assert.is_nil r.err
    assert.equals body, capture.processed[1].raw
    assert.equals "200", h2_response_status r.sent

  it "POST application/dns-message avec paramètres est traité", ->
    body = "\0\1\2\3"
    headers = h2_headers_frame 1, {
      { ":method", "POST" }
      { ":path", "/dns-query" }
      { "content-type", "application/dns-message; charset=binary" }
    }
    data = h2_frame_raw 0x0, 0x1, 1, body
    r = h2_run headers .. data
    assert.is_nil r.err
    assert.equals 1, #capture.processed
    assert.equals body, capture.processed[1].raw
    assert.equals "200", h2_response_status r.sent

  it "POST avec un content-type non DNS rend 415 sans traiter de DNS", ->
    headers = h2_headers_frame 1, {
      { ":method", "POST" }
      { ":path", "/dns-query" }
      { "content-type", "text/plain" }
    }
    data = h2_frame_raw 0x0, 0x1, 1, "\0\1\2\3"
    r = h2_run headers .. data
    assert.is_nil r.resp
    assert.equals "h2_status_415", r.err
    assert.equals 0, #capture.processed
    assert.equals "415", h2_response_status r.sent

  it "POST sans content-type rend 415 (parité HTTP/1.1)", ->
    headers = h2_headers_frame 1, {
      { ":method", "POST" }
      { ":path", "/dns-query" }
    }
    data = h2_frame_raw 0x0, 0x1, 1, "\0\1\2\3"
    r = h2_run headers .. data
    assert.is_nil r.resp
    assert.equals "h2_status_415", r.err
    assert.equals 0, #capture.processed
    assert.equals "415", h2_response_status r.sent

  it "GET JSON (Accept application/dns-json) rend le JSON DNS", ->
    capture.resp = string.char(0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0) ..
      "\7example\3com\0\0\1\0\1"
    frame = h2_headers_frame 1, {
      { ":method", "GET" }
      { ":path", "/dns-query?name=example.com&type=A" }
      { "accept", "application/dns-json" }
    }, true
    r = h2_run frame
    assert.is_nil r.err
    assert.equals 1, #capture.processed
    assert.equals "200", h2_response_status r.sent
    resp_headers = h2_response_headers r.sent
    assert.equals "application/dns-json", hpack.header_value(resp_headers, "content-type")
    assert.truthy h2_response_body(r.sent)\find '"Status":0', 1, true

  it "POST sur un autre chemin rend 404 sans traiter de DNS", ->
    frame = h2_headers_frame 1, {
      { ":method", "POST" }
      { ":path", "/autre" }
    }, true
    r = h2_run frame
    assert.is_nil r.resp
    assert.equals "h2_status_404", r.err
    assert.equals 0, #capture.processed
    assert.equals "404", h2_response_status r.sent

  it "GET sur un autre chemin rend 404 sans traiter de DNS", ->
    frame = h2_headers_frame 1, {
      { ":method", "GET" }
      { ":path", "/autre?dns=#{doh_query_b64}" }
    }, true
    r = h2_run frame
    assert.equals "h2_status_404", r.err
    assert.equals 0, #capture.processed
    assert.equals "404", h2_response_status r.sent

  it "méthode autre que GET/POST rend 405 sans traiter de DNS", ->
    frame = h2_headers_frame 1, {
      { ":method", "PUT" }
      { ":path", "/dns-query" }
    }, true
    r = h2_run frame
    assert.equals "h2_status_405", r.err
    assert.equals 0, #capture.processed
    assert.equals "405", h2_response_status r.sent

  it "GET sur /dns-query sans paramètre dns rend 400", ->
    frame = h2_headers_frame 1, {
      { ":method", "GET" }
      { ":path", "/dns-query" }
    }, true
    r = h2_run frame
    assert.equals "h2_status_400", r.err
    assert.equals 0, #capture.processed
    assert.equals "400", h2_response_status r.sent

  it "HEADERS sans pseudo-en-têtes rend 405", ->
    -- Bloc HPACK vide : décodable, mais ni :method ni :path.
    conn = make_h2_conn h2_frame_raw 0x1, 0x5, 1, ""
    resp, err = doh.handle_h2 conn, "1.2.3.4", nil, {}, nil
    assert.is_nil resp
    assert.equals "h2_status_405", err
    assert.equals "405", h2_response_status conn._sent!

  it "HEADERS PADDED + PRIORITY : remplit puis ignore les champs de contrôle", ->
    path = "/dns-query?dns=#{doh_query_b64}"
    block = hpack.encode {
      { ":method", "GET" }
      { ":scheme", "https" }
      { ":path", path }
    }
    -- pad length (3) + priorité (dépendance 0, poids 15) + bloc + padding.
    payload = string.char(3) .. "\0\0\0\0\x0f" .. block .. "\0\0\0"
    frame = h2_frame_raw 0x1, 0x2d, 1, payload
    r = h2_run frame
    assert.is_nil r.err
    assert.equals 1, #capture.processed
    assert.equals doh.b64url_decode(doh_query_b64), capture.processed[1].raw

  it "HEADERS PADDED avec padding hors payload → h2_headers_invalid", ->
    -- pad length 5 alors qu'il ne reste aucun octet.
    frame = h2_frame_raw 0x1, 0x0d, 1, "\x05"
    r = h2_run frame
    assert.is_nil r.resp
    assert.equals "h2_headers_invalid", r.err
    expected_goaway = string.char(0,0,8, 0x7, 0, 0,0,0,0, 0,0,0,0,0,0,0,1)
    assert.equals expected_goaway, r.sent\sub -17

  it "HEADERS sur le stream 0 → h2_protocol_error", ->
    block = hpack.encode { { ":method", "GET" }, { ":path", "/dns-query" } }
    frame = h2_frame_raw 0x1, 0x5, 0, block
    r = h2_run frame
    assert.equals "h2_protocol_error", r.err

  it "CONTINUATION d'un autre stream → h2_headers_invalid", ->
    headers = h2_frame_raw 0x1, 0x0, 1, "x"
    continuation = h2_frame_raw 0x9, 0x4, 3, ""
    r = h2_run headers .. continuation
    assert.equals "h2_headers_invalid", r.err

  it "bloc d'en-têtes cumulé supérieur à 65535 octets refusé", ->
    frames = { h2_frame_raw 0x1, 0x0, 1, string.rep("x", 16384) }
    for _ = 1, 3
      frames[#frames + 1] = h2_frame_raw 0x9, 0x0, 1, string.rep("x", 16384)
    r = h2_run table.concat frames
    assert.is_nil r.resp
    assert.equals "h2_headers_too_large", r.err

  it "bloc d'en-têtes réparti sur HEADERS + CONTINUATION", ->
    path = "/dns-query?dns=#{doh_query_b64}"
    block = hpack.encode {
      { ":method", "GET" }
      { ":scheme", "https" }
      { ":path", path }
    }
    mid = math.floor(#block / 2)
    headers = h2_frame_raw 0x1, 0x1, 1, block\sub(1, mid)
    continuation = h2_frame_raw 0x9, 0x4, 1, block\sub(mid + 1)
    r = h2_run headers .. continuation
    assert.is_nil r.err
    assert.equals 1, #capture.processed
    assert.equals doh.b64url_decode(doh_query_b64), capture.processed[1].raw

  it "bloc d'en-têtes indécodable → GOAWAY COMPRESSION_ERROR (0x9)", ->
    conn = make_h2_conn h2_frame_raw 0x1, 0x5, 1, "\x80"
    resp, err = doh.handle_h2 conn, "1.2.3.4", nil, {}, nil
    assert.is_nil resp
    assert.equals "h2_compression_error", err
    expected_goaway = string.char(0,0,8, 0x7, 0, 0,0,0,0, 0,0,0,0,0,0,0,9)
    assert.equals expected_goaway, conn._sent!\sub -17

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
  -- handshake_fn : contrôle complet de dohandshake (lever, non-réussite…).
  -- lines/raw : préface HTTP/2 et frames brutes pour les tests de la branche PRI.
  raw = opts.raw or ""
  lines = opts.lines or {}
  pos = 1
  line_idx = 0
  {
    dohandshake: ->
      return opts.handshake_fn! if opts.handshake_fn
      handshake_result, handshake_err
    selected_alpn: -> opts.alpn
    -- Méthodes (`=>`) : worker_doh appelle conn\receive/conn\send, le self
    -- implicite ne doit pas se substituer au mode/au payload.
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
    close: -> closed = true
    _sent: -> table.concat sent
    _closed: -> closed
  }

describe "worker_doh.handle_doh_client — routage HTTP/1.1", ->

  capture = {}
  before_each ->
    capture = { sent: {}, processed: {}, read_opts: nil, io_timeout: nil }
    reset_logs!
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

  it "réponse de refus DoH (REFUSED+EDE) : 200 application/dns-message, QR=1 RA=1", ->
    -- Une REFUSED de doh.query doit rester une réponse DoH valide pour Firefox
    -- (sinon TRR_RCODE_FAIL) : statut HTTP 200, content-type binaire, en-tête
    -- DNS de réponse. Cf. dns_ede.build_blocked_response.
    dns_ede = require "dns_ede"
    query = doh.build_dns_query "example.com", 1
    blocked = dns_ede.build_blocked_response {}, query, "denied"
    assert.is_not_nil blocked
    query_stub.process_query = (raw) -> blocked, nil
    run_client {
      method: "POST", path: "/dns-query"
      headers: { ["content-type"]: "application/dns-message" }
      body: query
    }
    assert.equals 200, capture.sent[1].status
    assert.equals "application/dns-message", capture.sent[1].headers["Content-Type"]
    assert.equals blocked, capture.sent[1].body
    parsed = require("ipparse.l7.dns").parse capture.sent[1].body, 1, false
    assert.is_true parsed.header.qr
    assert.is_true parsed.header.ra
    assert.equals 5, parsed.header.rcode

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

  it "POST sans content-type rend 415 (parité avec HTTP/2)", ->
    run_client {
      method: "POST", path: "/dns-query"
      headers: {}
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

-- ── Règles de chemin DoH (exportées, pures) ─────────────────────────────────

describe "worker_doh — règles de chemin DoH", ->

  it "is_doh_path : chemin non-string → false, sinon exact ou query string", ->
    assert.is_false doh.is_doh_path nil
    assert.is_false doh.is_doh_path 42
    assert.is_true doh.is_doh_path "/dns-query"
    assert.is_true doh.is_doh_path "/dns-query?dns=AAAB"
    assert.is_false doh.is_doh_path "/dns-queryx"
    assert.is_false doh.is_doh_path "/autre?dns=AAAB"

  it "is_dns_message_content_type : non-string → false", ->
    assert.is_false doh.is_dns_message_content_type nil
    assert.is_false doh.is_dns_message_content_type 42
    assert.is_true doh.is_dns_message_content_type "application/dns-message"

  it "dns_from_query : chemin non-string → nil", ->
    assert.is_nil doh.dns_from_query nil
    assert.is_nil doh.dns_from_query 42
    assert.is_not_nil doh.dns_from_query "/dns-query?dns=AAAB"

-- ── dns_response_json : listes à plusieurs éléments ─────────────────────────

describe "worker_doh — dns_response_json, listes multiples", ->

  it "sépare questions et réponses multiples d'une virgule", ->
    header = sp_dns ">H H H H H H", 0x1234, 0x8180, 2, 2, 0, 0
    q = qname_example_dns .. sp_dns ">H H", 1, QCLASS_IN
    rr = (ip) -> "\192\012" .. sp_dns ">H H I4 s2", 1, QCLASS_IN, 60, ip
    raw = header .. q .. q .. rr(string.char(1,2,3,4)) .. rr(string.char(5,6,7,8))
    json = doh.dns_response_json raw
    assert.truthy json\find "\"Question\":[{\"name\":\"example.com\",\"type\":1},{\"name\":\"example.com\",\"type\":1}]", 1, true
    assert.truthy json\find "\"data\":\"1.2.3.4\"},{", 1, true
    assert.truthy json\find "{\"name\":\"example.com\",\"type\":1,\"TTL\":60,\"data\":\"5.6.7.8\"}", 1, true

-- ── read_header_block (exportée) : branches d'erreur du bloc d'en-têtes ─────

describe "worker_doh.read_header_block", ->
  H2_PADDED = 0x8
  H2_PRIORITY = 0x20
  H2_END_HEADERS = 0x4
  H2_CONTINUATION = 0x9

  it "PADDED sur un payload vide → h2_headers_invalid", ->
    flags = bit.bor H2_PADDED, H2_END_HEADERS
    block, end_stream, err = doh.read_header_block make_h2_conn(""), 1, flags, ""
    assert.is_nil block
    assert.is_false end_stream
    assert.equals "h2_headers_invalid", err

  it "PRIORITY tronqué (< 5 octets) → h2_headers_invalid", ->
    flags = bit.bor H2_PRIORITY, H2_END_HEADERS
    block, end_stream, err = doh.read_header_block make_h2_conn(""), 1, flags, "abcd"
    assert.is_nil block
    assert.is_false end_stream
    assert.equals "h2_headers_invalid", err

  it "plus de 64 CONTINUATION → h2_headers_invalid (garde-fou)", ->
    frames = {}
    for _ = 1, 65
      frames[#frames + 1] = h2_frame_raw H2_CONTINUATION, 0x0, 1, "x"
    conn = make_h2_conn table.concat frames
    block, end_stream, err = doh.read_header_block conn, 1, 0x0, "frag"
    assert.is_nil block
    assert.equals "h2_headers_invalid", err

  it "CONTINUATION annonçant plus de 16 Ko → frame_too_large", ->
    header = string.char(0xFF, 0xFF, 0xFF, H2_CONTINUATION, 0x0, 0, 0, 0, 1)
    conn = make_h2_conn header
    block, end_stream, err = doh.read_header_block conn, 1, 0x0, "frag"
    assert.is_nil block
    assert.equals "frame_too_large", err

  it "flux interrompu pendant une CONTINUATION → h2_headers_invalid", ->
    conn = make_h2_conn ""
    block, end_stream, err = doh.read_header_block conn, 1, 0x0, "frag"
    assert.is_nil block
    assert.equals "h2_headers_invalid", err

-- ── make_server4 / make_server6 (exportés) : branches socket stubées ────────

make_srv_stub = (opts={}) ->
  rec = { opts: opts }
  {
    setoption: (self, name, value) ->
      rec.options = rec.options or {}
      rec.options[name] = value
      true
    bind: (self, addr, port) ->
      rec.bind = { addr, port }
      if opts.bind_raise
        error opts.bind_err or "bind failed"
      elseif opts.bind_fail
        nil, opts.bind_err or "address in use"
      else
        true
    listen: (self, backlog) ->
      rec.listen = backlog
      true
    settimeout: (self, t) ->
      rec.timeout = t
      true
    close: (self) ->
      rec.closed = true
    _rec: -> rec
  }

describe "worker_doh.make_server4/6", ->

  before_each ->
    socket_stub.tcp = (-> nil)
    socket_stub.tcp6 = (-> nil)

  it "make_server4 : succès → reuseaddr, listen(32), timeout 1", ->
    srv = make_srv_stub!
    socket_stub.tcp = (-> srv)
    out = doh.make_server4 8443
    assert.equals srv, out
    rec = srv._rec!
    assert.equals true, rec.options["reuseaddr"]
    assert.equals "0.0.0.0", rec.bind[1]
    assert.equals 8443, rec.bind[2]
    assert.equals 32, rec.listen
    assert.equals 1, rec.timeout

  it "make_server4 : bind échoue → nil + erreur, socket fermée", ->
    srv = make_srv_stub { bind_fail: true, bind_err: "address already in use" }
    socket_stub.tcp = (-> srv)
    out, err = doh.make_server4 8443
    assert.is_nil out
    assert.equals "address already in use", err
    assert.is_true srv._rec!.closed

  it "make_server6 : tcp6 indisponible (nil ou exception) → nil", ->
    socket_stub.tcp6 = (-> nil)
    assert.is_nil doh.make_server6 8443
    socket_stub.tcp6 = (-> error "IPv6 non supporté")
    assert.is_nil doh.make_server6 8443

  it "make_server6 : succès → v6only, bind ::, listen(32)", ->
    srv = make_srv_stub!
    socket_stub.tcp6 = (-> srv)
    out = doh.make_server6 8443
    assert.equals srv, out
    rec = srv._rec!
    assert.equals true, rec.options["ipv6-v6only"]
    assert.equals "::", rec.bind[1]
    assert.equals 32, rec.listen
    assert.equals 1, rec.timeout

  it "make_server6 : bind qui lève → nil, socket fermée", ->
    -- make_server6 pcall-e srv6.bind : seul un levé d'exception est capté
    -- (un simple `nil, err` de retour serait considéré comme un succès).
    srv = make_srv_stub { bind_raise: true, bind_err: "address already in use" }
    socket_stub.tcp6 = (-> srv)
    assert.is_nil doh.make_server6 8443
    assert.is_true srv._rec!.closed

-- ── handle_doh_client : branches d'erreur (certificats, TLS, handshake, PRI) ─

describe "worker_doh.handle_doh_client — branches d'erreur", ->
  capture = {}
  tls = nil

  build_args = (opts={}) ->
    {
      client: opts.client or make_client_stub!
      peer_ip: "192.0.2.10"
      state: {
        static_cert_paths: if opts.sni then nil else { key: "k", cert: "c" }
        cert_cache: {}
        client_timeout: opts.client_timeout or 7
        upstream: { marker: true }
      }
    }

  pri_request = ->
    { method: "PRI", path: "PRI * HTTP/2.0", headers: {}, body: "" }

  before_each ->
    reset_logs!
    capture = { read_request_called: false }
    cert_stub.load_static = (k, c) -> { ctx: true }
    cert_stub.load_or_generate_sni = (ip, cache) -> { ctx: true }
    tls = make_tls_stub {}
    ssl_stub.wrap = (sock, ctx) -> tls
    http_stub.read_request = (conn, opts) ->
      capture.read_request_called = true
      nil, "stub"
    http_stub.send_response = (conn, status, headers, body) ->
      capture.status = status
      nil
    http_stub.apply_io_timeouts = (conn, timeout) -> nil
    query_stub.process_query = (raw, ip, mac, up, vlan) -> "RESP_BYTES", nil

  it "certificat SNI dynamique : échec de lecture → request_read_failed, fermé", ->
    args = build_args { sni: true }
    doh.handle_doh_client args
    assert.equals 0, #log_errors
    assert.is_true has_record "request_read_failed"
    assert.is_true capture.read_request_called
    assert.is_true tls._closed!

  it "load_or_generate_sni lève : cert_gen_failed + conn_failed, client fermé", ->
    cert_stub.load_or_generate_sni = -> error "px5g absent"
    args = build_args { sni: true }
    doh.handle_doh_client args
    assert.is_true has_record "cert_gen_failed"
    assert.is_true has_record "conn_failed"
    rec = get_record "cert_gen_failed"
    assert.truthy tostring(rec.err)\find "px5g absent"
    assert.is_true args.client._closed!
    assert.is_false capture.read_request_called

  it "certificat SNI nul : cert_null (type sni) + conn_failed", ->
    cert_stub.load_or_generate_sni = (ip, cache) -> nil, "pas de px5g"
    args = build_args { sni: true }
    doh.handle_doh_client args
    rec = get_record "cert_null"
    assert.is_not_nil rec
    assert.equals "sni", rec.cert_type
    assert.is_true has_record "conn_failed"
    assert.is_true args.client._closed!

  it "certificat statique illisible : static_cert_child_failed + conn_failed", ->
    cert_stub.load_static = (k, c) -> nil, "PEM corrompu"
    args = build_args!
    doh.handle_doh_client args
    assert.is_true has_record "static_cert_child_failed"
    assert.is_true has_record "conn_failed"
    assert.is_true args.client._closed!
    assert.is_false capture.read_request_called

  it "ssl.wrap échoue : tls_wrap_failed, fermeture sans handshake", ->
    ssl_stub.wrap = (sock, ctx) -> nil, "wolfSSL manquant"
    args = build_args!
    doh.handle_doh_client args
    assert.is_true has_record "tls_wrap_failed"
    assert.is_true args.client._closed!
    assert.is_false capture.read_request_called

  it "dohandshake lève : handshake_error + handshake_failed, sans requête lue", ->
    tls = make_tls_stub { handshake_fn: -> error "dohandshake: fatal" }
    ssl_stub.wrap = (sock, ctx) -> tls
    args = build_args!
    doh.handle_doh_client args
    assert.is_true has_record "handshake_error"
    rec = get_record "handshake_error"
    assert.truthy tostring(rec.err)\find "dohandshake: fatal"
    assert.is_true has_record "handshake_failed"
    assert.is_true tls._closed!
    assert.is_false capture.read_request_called

  it "dohandshake ne réussit jamais : 50 tentatives puis max_attempts", ->
    attempts_seen = 0
    tls = make_tls_stub {
      handshake_fn: ->
        attempts_seen += 1
        false, nil
    }
    ssl_stub.wrap = (sock, ctx) -> tls
    args = build_args!
    doh.handle_doh_client args
    assert.equals 50, attempts_seen
    rec = get_record "handshake_failed"
    assert.is_not_nil rec
    assert.equals "max_attempts", rec.err
    assert.is_true tls._closed!
    assert.is_false capture.read_request_called

  it "sans méthode selected_alpn : journal tls_handshake_ok sans ALPN", ->
    tls = make_tls_stub { alpn: "h2" }
    tls.selected_alpn = nil
    ssl_stub.wrap = (sock, ctx) -> tls
    args = build_args!
    doh.handle_doh_client args
    assert.is_nil tls.selected_alpn
    assert.is_true has_record "tls_handshake_ok"
    assert.is_true has_record "request_read_failed"

  it "préface PRI (H2) : flux vide → h2_incomplete → h2_failed, fermé", ->
    tls = make_tls_stub { raw: "", lines: {} }
    ssl_stub.wrap = (sock, ctx) -> tls
    http_stub.read_request = (conn, opts) ->
      capture.read_request_called = true
      pri_request!
    args = build_args!
    doh.handle_doh_client args
    assert.is_true capture.read_request_called
    assert.is_true has_record "h2_failed"
    assert.is_true has_record "h2_request"
    assert.is_true tls._closed!

  it "préface PRI (H2) : 404 → h2_rejected journalisé", ->
    block = hpack.encode { { ":method", "GET" }, { ":path", "/autre" } }
    tls = make_tls_stub { raw: h2_frame_raw(0x1, 0x5, 1, block), lines: {} }
    ssl_stub.wrap = (sock, ctx) -> tls
    http_stub.read_request = (conn, opts) -> pri_request!
    args = build_args!
    doh.handle_doh_client args
    assert.is_true has_record("h2_rejected"), "actions: #{record_actions!}"
    assert.is_false has_record "h2_failed"
    assert.is_true tls._closed!

  it "préface PRI (H2) : requête DNS valide → h2_ok", ->
    b64 = "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"
    block = hpack.encode {
      { ":method", "GET" }
      { ":path", "/dns-query?dns=#{b64}" }
    }
    tls = make_tls_stub { raw: h2_frame_raw(0x1, 0x5, 1, block), lines: {} }
    ssl_stub.wrap = (sock, ctx) -> tls
    http_stub.read_request = (conn, opts) -> pri_request!
    args = build_args!
    doh.handle_doh_client args
    rec = get_record "h2_ok"
    assert.is_not_nil(rec), "actions: #{record_actions!}"
    assert.equals #"RESP_BYTES", rec.resp_bytes
    assert.is_true tls._closed!

-- ── handle_h2 : branches d'erreur d'écriture et cas limites ─────────────────

describe "worker_doh.handle_h2 — erreurs d'écriture et cas limites", ->
  processed = 0

  get_frames = ->
    h2_frame_raw 0x1, 0x5, 1, hpack.encode {
      { ":method", "GET" }
      { ":scheme", "https" }
      { ":path", "/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB" }
    }

  before_each ->
    reset_logs!
    processed = 0
    query_stub.process_query = (raw, ip, mac, up, vlan) ->
      processed += 1
      "RESP_BYTES", nil

  it "échec d'écriture du SETTINGS serveur → erreur immédiate", ->
    conn = make_h2_conn "", { fail_after: 0 }
    resp, err = doh.handle_h2 conn, "1.2.3.4", nil, {}, nil
    assert.is_nil resp
    assert.equals "send_timeout", err

  it "SETTINGS client sans ACK → SETTINGS ACK émis", ->
    frames = table.concat {
      h2_frame_raw 0x4, 0x0, 0, ""
      get_frames!
    }
    conn = make_h2_conn frames
    resp, err = doh.handle_h2 conn, "1.2.3.4", nil, {}, nil
    assert.is_nil err
    assert.equals "RESP_BYTES", resp
    ack_seen = false
    for f in *h2_parse_frames conn._sent!
      ack_seen = true if f[1] == 0x4 and bit.band(f[2], 0x1) != 0
    assert.is_true ack_seen

  it "échec d'écriture du SETTINGS ACK → interruption", ->
    frames = table.concat {
      h2_frame_raw 0x4, 0x0, 0, ""
      get_frames!
    }
    conn = make_h2_conn frames, { fail_after: 1 }
    resp, err = doh.handle_h2 conn, "1.2.3.4", nil, {}, nil
    assert.is_nil resp
    assert.equals "send_timeout", err

  it "PING client sans ACK → PING ACK émis, requête servie", ->
    frames = table.concat {
      h2_frame_raw 0x6, 0x0, 0, "pingdata"
      get_frames!
    }
    conn = make_h2_conn frames
    resp, err = doh.handle_h2 conn, "1.2.3.4", nil, {}, nil
    assert.is_nil err
    assert.equals "RESP_BYTES", resp
    ping_ack = false
    for f in *h2_parse_frames conn._sent!
      ping_ack = true if f[1] == 0x6 and bit.band(f[2], 0x1) != 0
    assert.is_true ping_ack

  it "échec d'écriture du PING ACK → interruption", ->
    frames = h2_frame_raw 0x6, 0x0, 0, "pingdata"
    conn = make_h2_conn frames, { fail_after: 1 }
    resp, err = doh.handle_h2 conn, "1.2.3.4", nil, {}, nil
    assert.is_nil resp
    assert.equals "send_timeout", err

  it "HEADERS sans END_STREAM puis flux terminé → h2_incomplete + GOAWAY", ->
    frame = h2_frame_raw 0x1, 0x4, 1, hpack.encode {
      { ":method", "GET" }
      { ":path", "/dns-query" }
    }
    conn = make_h2_conn frame
    resp, err = doh.handle_h2 conn, "1.2.3.4", nil, {}, nil
    assert.is_nil resp
    assert.equals "h2_incomplete", err
    assert.equals 0, processed
    expected_goaway = string.char(0,0,8, 0x7, 0, 0,0,0,0, 0,0,0,0,0,0,0,1)
    assert.equals expected_goaway, conn._sent!\sub -17

  it "POST avec corps DATA vide → 400 sans requête DNS", ->
    headers = h2_frame_raw 0x1, 0x4, 1, hpack.encode {
      { ":method", "POST" }
      { ":path", "/dns-query" }
      { "content-type", "application/dns-message" }
    }
    data = h2_frame_raw 0x0, 0x1, 1, ""
    conn = make_h2_conn headers .. data
    resp, err = doh.handle_h2 conn, "1.2.3.4", nil, {}, nil
    assert.is_nil resp
    assert.equals "h2_status_400", err
    assert.equals 0, processed

  it "échec de process_query → GOAWAY 0x2 et h2_query_error", ->
    query_stub.process_query = (raw, ip, mac, up, vlan) -> nil, "amont muet"
    conn = make_h2_conn get_frames!
    resp, err = doh.handle_h2 conn, "1.2.3.4", nil, {}, nil
    assert.is_nil resp
    assert.equals "h2_query_error", err
    rec = get_record "h2_query_error"
    assert.is_not_nil rec
    assert.equals "amont muet", rec.err

  it "échec d'écriture des en-têtes de réponse → erreur transmise", ->
    conn = make_h2_conn get_frames!, { fail_after: 1 }
    resp, err = doh.handle_h2 conn, "1.2.3.4", nil, {}, nil
    assert.is_nil resp
    assert.equals "send_timeout", err

  it "échec d'écriture du corps de réponse → erreur transmise", ->
    conn = make_h2_conn get_frames!, { fail_after: 2 }
    resp, err = doh.handle_h2 conn, "1.2.3.4", nil, {}, nil
    assert.is_nil resp
    assert.equals "send_timeout", err

  it "échec d'écriture d'une réponse de rejet (404) → erreur transmise", ->
    frame = h2_frame_raw 0x1, 0x5, 1, hpack.encode {
      { ":method", "POST" }
      { ":path", "/autre" }
    }
    conn = make_h2_conn frame, { fail_after: 1 }
    resp, err = doh.handle_h2 conn, "1.2.3.4", nil, {}, nil
    assert.is_nil resp
    assert.equals "send_timeout", err

  it "CONTINUATION annonçant 16 Mo → GOAWAY FRAME_SIZE_ERROR", ->
    headers = h2_frame_raw 0x1, 0x0, 1, "frag"
    oversize = string.char(0xFF, 0xFF, 0xFF, 0x9, 0x0, 0, 0, 0, 1)
    conn = make_h2_conn headers .. oversize
    resp, err = doh.handle_h2 conn, "1.2.3.4", nil, {}, nil
    assert.is_nil resp
    assert.equals "h2_frame_too_large", err
    assert.equals string.char(6), conn._sent!\sub -1

-- ── doh_child_fn (extrait de run) ───────────────────────────────────────────

describe "worker_doh.doh_child_fn", ->

  before_each ->
    reset_logs!
    cert_stub.load_static = (k, c) -> nil, "stub"
    http_stub.read_request = (conn, opts) -> nil, "stub"
    http_stub.send_response = (conn, status, headers, body) -> nil
    http_stub.apply_io_timeouts = (conn, timeout) -> nil

  it "amont injoignable : upstream_open_failed, client fermé, sans traitement", ->
    closed = false
    up_closed = false
    args = {
      client: { close: -> closed = true }
      peer_ip: "192.0.2.77"
      state: {
        make_upstream: -> nil, "refus par l'amont"
        close_upstream: (up) -> up_closed = true
        cert_cache: {}
        client_timeout: 1
        static_cert_paths: { key: "k", cert: "c" }
      }
    }
    doh.doh_child_fn args
    assert.is_nil args.state.upstream
    assert.is_true closed
    assert.is_false up_closed
    rec = get_record "upstream_open_failed"
    assert.is_not_nil rec
    assert.equals "192.0.2.77", rec.peer
    assert.equals "refus par l'amont", rec.err

  it "amont ouvert : state.upstream positionné, délégation, amont refermé", ->
    up_closed = nil
    client = make_client_stub!
    args = {
      client: client
      peer_ip: "192.0.2.78"
      state: {
        make_upstream: -> { marker: "up" }
        close_upstream: (up) -> up_closed = up
        cert_cache: {}
        client_timeout: 1
        static_cert_paths: { key: "k", cert: "c" }
      }
    }
    doh.doh_child_fn args
    assert.same { marker: "up" }, args.state.upstream
    assert.same { marker: "up" }, up_closed
    -- handle_doh_client s'est bien exécuté (échec certicat géré et journalisé)
    assert.is_true has_record "static_cert_child_failed"
    assert.is_true has_record "conn_failed"

-- ── run : configuration et décisions (sans boucle d'E/S) ────────────────────
-- `run` ne retourne jamais : les tests passent par pcall et sortent à
-- l'entrée de la boucle d'acceptation (reap_one → nil, puis socket.select qui
-- lève). Aucune connexion acceptée ni enfant forké : cette boucle reste
-- couverte par les tests e2e ; seules les décisions de configuration sont
-- visées ici.
describe "worker_doh.run", ->
  saved_modules = {}
  nft_calls = {}

  stub_module = (name, mod) ->
    saved_modules[#saved_modules + 1] = { name, package.loaded[name] }
    package.loaded[name] = mod

  restore_modules = ->
    for i = #saved_modules, 1, -1
      entry = saved_modules[i]
      package.loaded[entry[1]] = entry[2]
    saved_modules = {}

  make_filter_stub = ->
    {
      get_auth_cfg: ->
        { redirect_url: "http://10.0.0.1:33443/captive?to=x", bridge_ifname: nil }
    }

  make_captive_stub = (initial, ensured) ->
    {
      domain_from_url: (url) -> "portal.example"
      new_detector: (auth) -> {
        get: (=> initial[1], initial[2])
        ensure: (=> ensured[1], ensured[2])
      }
    }

  make_filter_data = ->
    { rules: { rules_metadata: { marker: true } }, auth_cfg_cache: {}, decision_cfg: {} }

  run_cfg = (overrides={}) ->
    base = {
      enabled: true
      port: 8443
      upstream_ip: "192.0.2.53"
      upstream_port: 53
      timeout_ms: 100
      cert: "tmp/doh_spec/missing-cert.pem"
      key: "tmp/doh_spec/missing-key.pem"
      client_timeout: 5
      nft_wfd: 7
      ack_rfd: 8
      worker_idx: 3
    }
    for k, v in pairs overrides
      base[k] = v
    base

  before_each ->
    reset_logs!
    captive_sets = {}
    wildcard_meta = nil
    nft_calls = {}
    saved_modules = {}
    cert_stub.load_static = (k, c) -> nil, "stub"
    upstream_select_result = nil
    upstream_select_err = "stub"
    socket_stub.tcp = (-> make_srv_stub!)
    socket_stub.tcp6 = (-> make_srv_stub!)
    socket_stub.select = (-> error "hors périmètre : boucle d'E/S laissée aux tests e2e")
    stub_module "nft_queue", {
      set_wfd: (fd) -> nft_calls[#nft_calls + 1] = { "wfd", fd }
      set_ack_rfd: (fd, idx) -> nft_calls[#nft_calls + 1] = { "ack_rfd", fd, idx }
    }
    stub_module "auth.cert_cache", {
      create_cache: (n, ttl, dir) -> { set: (->), get: (-> nil) }
    }

  after_each ->
    restore_modules!

  it "désactivé : canaux nft configurés puis retour immédiat", ->
    ok, err = pcall doh.run, { enabled: false, port: 8443, nft_wfd: 7, ack_rfd: 8, worker_idx: 3 }, nil
    assert.is_true ok, tostring(err)
    assert.is_true has_record "worker_disabled"
    assert.equals 2, #nft_calls
    assert.same({ "wfd", 7 }, nft_calls[1])
    assert.same({ "ack_rfd", 8, 3 }, nft_calls[2])

  it "filter_data : règles transmises, portail captif, avertissements IP manquants", ->
    stub_module "filter", make_filter_stub!
    stub_module "captive_ips", make_captive_stub({ nil, nil }, { nil, nil })
    fd = make_filter_data!
    ok, err = pcall doh.run, { enabled: false, port: 8443 }, fd
    assert.is_true ok, tostring(err)
    filter_stub = package.loaded["filter"]
    assert.same fd.rules, filter_stub.rules
    assert.same fd.auth_cfg_cache, filter_stub.auth_cfg_cache
    assert.same fd.decision_cfg, filter_stub.decision_cfg
    assert.same fd.rules.rules_metadata, wildcard_meta
    assert.equals 1, #captive_sets
    assert.same({ domain: "portal.example" }, captive_sets[1])
    assert.is_true has_record "captive_ip4_not_detected"
    assert.is_true has_record "captive_ip6_not_detected"

  it "installation : cert statique invalide, repli UDP, arrêt à l'entrée de boucle", ->
    stub_module "filter", make_filter_stub!
    stub_module "captive_ips", make_captive_stub({ "10.0.0.98", "fd00::98" }, { "10.0.0.99", "fd00::98" })
    ok, err = pcall doh.run, run_cfg!, make_filter_data!
    assert.is_false ok
    assert.truthy tostring(err)\find "hors périmètre"
    assert.is_true has_record "worker_start"
    assert.is_true has_record "server_listening"
    assert.is_true has_record "static_cert_load_failed"
    assert.is_false has_record "static_cert_loaded"
    assert.is_false has_record "upstream_doh_unavailable_udp"
    -- détection captive paresseuse en tête de boucle : IP4 changée → mise à jour
    assert.equals 2, #captive_sets
    assert.same({ domain: "portal.example", ip4: "10.0.0.99", ip6: "fd00::98" }, captive_sets[2])

  it "certificat statique valide : chargé, contrôle d'échéance, transport DoH retenu", ->
    cert_stub.load_static = (k, c) -> { ctx: true }
    upstream_select_result = {
      transport: "curl"
      verify_tls: true
      make_client: (->)
      close: (->)
    }
    upstream_select_err = nil
    ok, err = pcall doh.run, run_cfg({ upstream_doh_url: "https://dns.example/dns-query" }), nil
    assert.is_false ok
    assert.truthy(tostring(err)\find("hors périmètre"), "err: #{tostring(err)}")
    assert.is_true has_record "static_cert_loaded"
    assert.is_false has_record "static_cert_load_failed"

  it "transport DoH amont indisponible → repli UDP/53 journalisé", ->
    upstream_select_result = nil
    upstream_select_err = "curl load_failed"
    ok, err = pcall doh.run, run_cfg({ upstream_doh_url: "https://dns.example/dns-query" }), nil
    assert.is_false ok
    assert.truthy(tostring(err)\find("hors périmètre"), "err: #{tostring(err)}")
    assert.is_true has_record "upstream_doh_unavailable_udp"

  it "port déjà pris : error au bind avant la boucle", ->
    socket_stub.tcp = (-> make_srv_stub({ bind_fail: true, bind_err: "address already in use" }))
    ok, err = pcall doh.run, run_cfg!, nil
    assert.is_false ok
    assert.truthy tostring(err)\find "DoH: cannot bind port 8443"
    assert.truthy tostring(err)\find "address already in use"
