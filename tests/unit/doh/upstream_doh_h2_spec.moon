-- tests/unit/doh/upstream_doh_h2_spec.moon
-- Chemin HTTP/2 du client DoH de repli (ALPN h2 négocié), sans I/O réseau :
-- un faux TLS sert des trames HTTP/2 fabriquées et capture les octets émis.

sp = require("ipparse.lib.pack_compat").pack
bit = require "bit"
h2f  = require "doh.h2_frames"
hpack = require "doh.hpack"

eval_log = (f) -> (type(f) == "function") and f!
package.loaded["log"] = {
  log_warn: eval_log, log_debug: eval_log, log_info: eval_log
}

make_dns_req = (txid=0x1234) ->
  sp ">H H H H H H", txid, 0x0100, 1, 0, 0, 0
make_dns_resp = (txid=0x1234) ->
  sp ">H H H H H H", txid, 0x8180, 1, 1, 0, 0
dns_req  = make_dns_req 0x1234
dns_resp = make_dns_resp 0x1234

-- Fabrique les octets d'une frame HTTP/2 via l'écrivain partagé.
frame_bytes = (ftype, flags, sid, payload) ->
  out = ""
  conn = {
    send: (data) =>
      out = out .. data
      #data
  }
  ok = h2f.h2_write_frame conn, ftype, flags, sid, payload
  assert.is_true ok
  out

-- Faux TLS : sert un flux d'octets par tranches d'au plus n octets.
-- `selected_alpn` simule la négociation ALPN ("h2" ou nil).
make_h2_tls = (bytes, alpn="h2") ->
  pos = 1
  sent = ""
  {
    doconnect: -> true
    selected_alpn: -> alpn
    send: (data) =>
      sent = sent .. data
      #data
    receive: (n) =>
      return nil, "eof_from_peer" if pos > #bytes
      take = math.min n, #bytes - pos + 1
      chunk = bytes\sub pos, pos + take - 1
      pos += take
      chunk
    close: => @closed = true
    closed: false
    _sent: -> sent
  }

make_ssl_stub = (tls_stub) ->
  {
    verification_available: -> true, nil, "/etc/ssl/certs/ca-certificates.crt"
    newclient_context: (opts) ->
      { ctx: "stub_ctx", closed: false, is_client: true, verify_peer: opts.verify_peer }
    wrap: (sock, ctx, opts) -> tls_stub
    free_context: (->)
  }

make_socket_stub = ->
  sock = {
    fd: 42
    closed: false
    connect: (host, port) => true
    close: => @closed = true
  }
  {
    create_tcp: -> sock
    create_tcp6: -> sock
    C: { setsockopt: (fd, ...) -> 0 }
    SOL_SOCKET: 1
    SO_RCVTIMEO: 20
    SO_SNDTIMEO: 21
  }

load_mod = (tls_stub) ->
  package.loaded["auth.ffi_wolfssl"] = make_ssl_stub tls_stub
  package.loaded["lib.socket"] = make_socket_stub!
  package.loaded["doh.upstream_doh"] = nil
  require "doh.upstream_doh"

-- Sépare le flux émis par le client en frames (préface exclue).
parse_client_frames = (sent) ->
  assert.equals "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", sent\sub 1, 24
  frames = {}
  pos = 25
  while pos + 8 <= #sent
    len = sent\byte(pos) * 65536 + sent\byte(pos + 1) * 256 + sent\byte(pos + 2)
    ftype = sent\byte(pos + 3)
    flags = sent\byte(pos + 4)
    sid = sent\byte(pos + 5) * 16777216 + sent\byte(pos + 6) * 65536 +
      sent\byte(pos + 7) * 256 + sent\byte(pos + 8)
    payload = sent\sub pos + 9, pos + 8 + len
    frames[#frames + 1] = { :ftype, :flags, :sid, :payload }
    pos += 9 + len
  frames

status_block = (status="200") ->
  hpack.encode { { ":status", status }, { "content-type", "application/dns-message" } }

describe "doh.upstream_doh (HTTP/2)", ->

  it "ALPN http/1.1 → comportement HTTP/1.1 inchangé", ->
    tls = make_h2_tls "", "http/1.1"
    mod = load_mod tls
    h = mod.new_client "https://1.1.1.1/dns-query"
    assert.equals "http/1.1", h.alpn
    assert.is_false h.h2

  it "ALPN h2 → handle.h2, préface, requête et corps DNS", ->
    bytes = table.concat {
      frame_bytes h2f.H2_FRAME_SETTINGS, 0, 0, ""
      frame_bytes h2f.H2_FRAME_HEADERS, h2f.H2_FLAG_END_HEADERS, 1, status_block!
      frame_bytes h2f.H2_FRAME_DATA, h2f.H2_FLAG_END_STREAM, 1, dns_resp
    }
    tls = make_h2_tls bytes, "h2"
    mod = load_mod tls
    h, err = mod.new_client "https://1.1.1.1/dns-query"
    assert.is_nil err
    assert.equals "h2", h.alpn
    assert.is_true h.h2
    body, qerr = mod.query h, dns_req
    assert.is_nil qerr
    assert.equals dns_resp, body

    sent = tls._sent!
    assert.equals "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", sent\sub 1, 24
    assert.truthy sent\find dns_req, 1, true
    -- ACK du SETTINGS serveur émis (type 4, flag ACK).
    frames = parse_client_frames sent
    has_settings_ack = false
    has_headers = false
    for fr in *frames
      has_settings_ack = true if fr.ftype == h2f.H2_FRAME_SETTINGS and fr.flags == h2f.H2_FLAG_ACK
      has_headers = true if fr.ftype == h2f.H2_FRAME_HEADERS and fr.sid == 1
    assert.is_true has_settings_ack
    assert.is_true has_headers

  it "bloc HEADERS : :method POST, :scheme https, :authority, :path, content-type", ->
    bytes = table.concat {
      frame_bytes h2f.H2_FRAME_SETTINGS, 0, 0, ""
      frame_bytes h2f.H2_FRAME_HEADERS, h2f.H2_FLAG_END_HEADERS, 1, status_block!
      frame_bytes h2f.H2_FRAME_DATA, h2f.H2_FLAG_END_STREAM, 1, dns_resp
    }
    tls = make_h2_tls bytes, "h2"
    mod = load_mod tls
    h = mod.new_client "https://1.1.1.1/dns-query"
    mod.query h, dns_req
    frames = parse_client_frames tls._sent!
    block = nil
    for fr in *frames
      block = fr.payload if fr.ftype == h2f.H2_FRAME_HEADERS and fr.sid == 1
    assert.is_not_nil block
    headers, derr = hpack.decode hpack.new_decoder!, block
    assert.is_nil derr
    assert.equals "POST", hpack.header_value headers, ":method"
    assert.equals "https", hpack.header_value headers, ":scheme"
    assert.equals "1.1.1.1", hpack.header_value headers, ":authority"
    assert.equals "/dns-query", hpack.header_value headers, ":path"
    assert.equals "application/dns-message", hpack.header_value headers, "content-type"
    assert.equals "application/dns-message", hpack.header_value headers, "accept"
    assert.equals tostring(#dns_req), hpack.header_value headers, "content-length"

  it "HEADERS + CONTINUATION sur deux trames → réponse acceptée", ->
    block = status_block!
    mid = math.floor #block / 2
    bytes = table.concat {
      frame_bytes h2f.H2_FRAME_SETTINGS, 0, 0, ""
      frame_bytes h2f.H2_FRAME_HEADERS, 0, 1, block\sub(1, mid)
      frame_bytes h2f.H2_FRAME_CONTINUATION, h2f.H2_FLAG_END_HEADERS, 1, block\sub(mid + 1)
      frame_bytes h2f.H2_FRAME_DATA, h2f.H2_FLAG_END_STREAM, 1, dns_resp
    }
    tls = make_h2_tls bytes, "h2"
    mod = load_mod tls
    h = mod.new_client "https://1.1.1.1/dns-query"
    body, err = mod.query h, dns_req
    assert.is_nil err
    assert.equals dns_resp, body

  it "WINDOW_UPDATE émis pour les DATA reçues", ->
    bytes = table.concat {
      frame_bytes h2f.H2_FRAME_SETTINGS, 0, 0, ""
      frame_bytes h2f.H2_FRAME_HEADERS, h2f.H2_FLAG_END_HEADERS, 1, status_block!
      frame_bytes h2f.H2_FRAME_DATA, h2f.H2_FLAG_END_STREAM, 1, dns_resp
    }
    tls = make_h2_tls bytes, "h2"
    mod = load_mod tls
    h = mod.new_client "https://1.1.1.1/dns-query"
    mod.query h, dns_req
    found = false
    for fr in *parse_client_frames tls._sent!
      found = true if fr.ftype == h2f.H2_FRAME_WINDOW_UPDATE
    assert.is_true found

  it "PING serveur → PING ACK renvoyé, réponse traitée", ->
    ping = "abcdefgh"
    bytes = table.concat {
      frame_bytes h2f.H2_FRAME_SETTINGS, 0, 0, ""
      frame_bytes h2f.H2_FRAME_PING, 0, 0, ping
      frame_bytes h2f.H2_FRAME_HEADERS, h2f.H2_FLAG_END_HEADERS, 1, status_block!
      frame_bytes h2f.H2_FRAME_DATA, h2f.H2_FLAG_END_STREAM, 1, dns_resp
    }
    tls = make_h2_tls bytes, "h2"
    mod = load_mod tls
    h = mod.new_client "https://1.1.1.1/dns-query"
    body, err = mod.query h, dns_req
    assert.is_nil err
    assert.equals dns_resp, body
    acked = false
    for fr in *parse_client_frames tls._sent!
      if fr.ftype == h2f.H2_FRAME_PING and fr.flags == h2f.H2_FLAG_ACK
        assert.equals ping, fr.payload
        acked = true
    assert.is_true acked

  it "trailers (HEADERS sans :status) après DATA → ignorés, réponse acceptée", ->
    bytes = table.concat {
      frame_bytes h2f.H2_FRAME_SETTINGS, 0, 0, ""
      frame_bytes h2f.H2_FRAME_HEADERS, h2f.H2_FLAG_END_HEADERS, 1, status_block!
      frame_bytes h2f.H2_FRAME_DATA, 0, 1, dns_resp
      frame_bytes h2f.H2_FRAME_HEADERS,
        bit.bor(h2f.H2_FLAG_END_HEADERS, h2f.H2_FLAG_END_STREAM), 1,
        hpack.encode { { "x-trailer", "1" } }
    }
    tls = make_h2_tls bytes, "h2"
    mod = load_mod tls
    h = mod.new_client "https://1.1.1.1/dns-query"
    body, err = mod.query h, dns_req
    assert.is_nil err
    assert.equals dns_resp, body

  it "statut ≠ 200 → nil + http_status_500, connexion fermée", ->
    bytes = table.concat {
      frame_bytes h2f.H2_FRAME_SETTINGS, 0, 0, ""
      frame_bytes h2f.H2_FRAME_HEADERS,
        bit.bor(h2f.H2_FLAG_END_HEADERS, h2f.H2_FLAG_END_STREAM), 1, status_block("500")
    }
    tls = make_h2_tls bytes, "h2"
    mod = load_mod tls
    h = mod.new_client "https://1.1.1.1/dns-query"
    body, err = mod.query h, dns_req
    assert.is_nil body
    assert.truthy err\find "http_status_500", 1, true
    assert.is_true tls.closed

  it "GOAWAY → nil + h2_goaway, connexion fermée", ->
    bytes = table.concat {
      frame_bytes h2f.H2_FRAME_SETTINGS, 0, 0, ""
      frame_bytes h2f.H2_FRAME_GOAWAY, 0, 0, "\0\0\0\0\0\0\0\0"
    }
    tls = make_h2_tls bytes, "h2"
    mod = load_mod tls
    h = mod.new_client "https://1.1.1.1/dns-query"
    body, err = mod.query h, dns_req
    assert.is_nil body
    assert.truthy err\find "h2_goaway", 1, true
    assert.is_true tls.closed

  it "RST_STREAM → nil + h2_rst_stream, connexion fermée", ->
    bytes = table.concat {
      frame_bytes h2f.H2_FRAME_SETTINGS, 0, 0, ""
      frame_bytes h2f.H2_FRAME_RST_STREAM, 0, 1, "\0\0\0\0"
    }
    tls = make_h2_tls bytes, "h2"
    mod = load_mod tls
    h = mod.new_client "https://1.1.1.1/dns-query"
    body, err = mod.query h, dns_req
    assert.is_nil body
    assert.truthy err\find "h2_rst_stream", 1, true
    assert.is_true tls.closed

  it "corps cumulé > MAX_DNS_BODY → nil + body_too_large", ->
    big = string.rep "x", 16384
    frames = {
      frame_bytes h2f.H2_FRAME_SETTINGS, 0, 0, ""
      frame_bytes h2f.H2_FRAME_HEADERS, h2f.H2_FLAG_END_HEADERS, 1, status_block!
    }
    for _ = 1, 4
      frames[#frames + 1] = frame_bytes h2f.H2_FRAME_DATA, 0, 1, big
    tls = make_h2_tls table.concat(frames), "h2"
    mod = load_mod tls
    h = mod.new_client "https://1.1.1.1/dns-query"
    body, err = mod.query h, dns_req
    assert.is_nil body
    assert.truthy err\find "body_too_large", 1, true
    assert.is_true tls.closed

  it "trame tronquée → nil + erreur propre, connexion fermée", ->
    truncated = string.char(0, 0, 100, 0, 0, 0, 0, 0, 1) .. "short"
    tls = make_h2_tls truncated, "h2"
    mod = load_mod tls
    h = mod.new_client "https://1.1.1.1/dns-query"
    body, err = mod.query h, dns_req
    assert.is_nil body
    assert.is_not_nil err
    assert.is_true tls.closed

  it "DATA arrivée avant HEADERS puis END_STREAM → missing_status", ->
    bytes = table.concat {
      frame_bytes h2f.H2_FRAME_DATA, h2f.H2_FLAG_END_STREAM, 1, dns_resp
    }
    tls = make_h2_tls bytes, "h2"
    mod = load_mod tls
    h = mod.new_client "https://1.1.1.1/dns-query"
    body, err = mod.query h, dns_req
    assert.is_nil body
    assert.truthy err\find "missing_status", 1, true
    assert.is_true tls.closed
