-- src/worker_doh.moon
-- DoH (DNS-over-HTTPS) worker.
--
-- Listens on DOH_PORT (default 8443) with TLS (same cert strategy as AUTH:
-- static cert if configured, otherwise dynamic SNI via px5g/cert_cache).
-- For each connection, forks a short-lived child that:
--   1. Performs TLS handshake.
--   2. Reads an HTTP/1.1 request (POST or GET /dns-query).
--   3. Calls doh.query.process_query() which filters + forwards + injects nft.
--   4. Returns 200 application/dns-message (or 200 REFUSED if blocked).
--
-- The worker exits immediately if DOH_ENABLED ~= "1".

socket  = require "lib.socket"
ssl     = require "auth.ffi_wolfssl"
bit     = require "bit"

{ :fork_child, :reap_one }              = require "lib.process"
{ :load_or_generate_sni, :load_static } = require "auth.cert"
{ :log_info, :log_warn, :log_error, :log_debug, :set_action_prefix } = require "log"
{ :read_request, :send_response }       = require "lib.http"
{ :get_mac }                            = require "mac_learner_ipc"
{ :process_query }                      = require "doh.query"
{ :parse, :types, :rcodes }              = require "ipparse.l7.dns"
upstream_mod                            = require "doh.upstream"

-- ── Base64url decoder (RFC 4648 §5, no padding required) ────────────────────

b64_chars = {}
do
  s = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  for i = 1, #s
    b64_chars[s\sub(i, i)] = i - 1
  -- url-safe replacements
  b64_chars["-"] = 62
  b64_chars["_"] = 63

--- Decode a base64url-encoded string to raw bytes.
-- @tparam string s Base64url input (padding optional).
-- @treturn string|nil Decoded bytes, or nil on decode error.
b64url_decode = (s) ->
  s = s\gsub "%-", "-"\gsub "_", "_"  -- already url-safe chars; normalise padding
  -- add missing padding
  pad = (4 - #s % 4) % 4
  s = s .. string.rep "=", pad

  out = {}
  i = 1
  while i <= #s
    c1 = b64_chars[s\sub(i,   i)  ] or -1
    c2 = b64_chars[s\sub(i+1, i+1)] or -1
    c3 = b64_chars[s\sub(i+2, i+2)] or -1
    c4 = b64_chars[s\sub(i+3, i+3)] or -1
    break if c1 < 0 or c2 < 0
    v = c1 * 0x40000 + c2 * 0x1000 + (c3 >= 0 and c3 or 0) * 0x40 + (c4 >= 0 and c4 or 0)
    out[#out + 1] = string.char bit.band(bit.rshift(v, 16), 0xFF)
    if c3 >= 0
      out[#out + 1] = string.char bit.band(bit.rshift(v, 8), 0xFF)
    if c4 >= 0
      out[#out + 1] = string.char bit.band(v, 0xFF)
    i += 4
  table.concat out

url_decode = (s) ->
  return "" unless s
  s = s\gsub "%+", " "
  s\gsub "%%(%x%x)", (h) -> string.char tonumber h, 16

query_param = (path, name) ->
  val = path\match "[?&]#{name}=([^&]+)"
  url_decode val if val

json_escape = (s) ->
  return "" unless s
  s = tostring s
  s = s\gsub "\\", "\\\\"
  s = s\gsub "\"", "\\\""
  s = s\gsub "\n", "\\n"
  s = s\gsub "\r", "\\r"
  s = s\gsub "\t", "\\t"
  s

json_quote = (s) -> "\"" .. json_escape(s) .. "\""

qtype_from_name = (name) ->
  return 1 unless name
  n = tonumber name
  return n if n
  types[name\upper!] or 1

encode_qname = (name) ->
  return nil unless name and #name > 0
  name = name\gsub "%.$", ""
  parts = {}
  for label in name\gmatch "[^%.]+"
    return nil if #label > 63
    parts[#parts + 1] = string.char(#label) .. label
  table.concat(parts) .. "\0"

u16 = (n) -> string.char(bit.band(bit.rshift(n, 8), 0xFF)) .. string.char(bit.band(n, 0xFF))
build_dns_query = (name, qtype) ->
  qname = encode_qname name
  return nil unless qname
  id = os.time! % 65536
  table.concat {
    u16 id
    u16 0x0100
    u16 1
    u16 0
    u16 0
    u16 0
    qname
    u16 qtype
    u16 1
  }

rr_data_json = (rr) ->
  if rr.rtype == 1 and #rr.rdata == 4
    return "#{rr.rdata\byte(1)}.#{rr.rdata\byte(2)}.#{rr.rdata\byte(3)}.#{rr.rdata\byte(4)}"
  if rr.rtype == 28 and #rr.rdata == 16
    words = {}
    for i = 1, 16, 2
      words[#words + 1] = string.format "%x", rr.rdata\byte(i) * 256 + rr.rdata\byte(i + 1)
    return table.concat words, ":"
  rr.rdata or ""

dns_response_json = (raw) ->
  dns = parse raw, 1, false
  return nil unless dns
  parts = {
    "{"
    "\"Status\":" .. tostring(dns.header.rcode or 0)
    ",\"TC\":" .. tostring(dns.header.tc and true or false)
    ",\"RD\":" .. tostring(dns.header.rd and true or false)
    ",\"RA\":" .. tostring(dns.header.ra and true or false)
    ",\"Question\":["
  }
  questions = dns.questions or {}
  for i, q in ipairs questions
    parts[#parts + 1] = "," if i > 1
    parts[#parts + 1] = "{\"name\":" .. json_quote(q.name or "") .. ",\"type\":" .. tostring(q.qtype or 1) .. "}"
  parts[#parts + 1] = "],\"Answer\":["
  answers = dns.answers or {}
  n = 0
  for rr in *answers
    if rr.rtype == 1 or rr.rtype == 28
      n += 1
      parts[#parts + 1] = "," if n > 1
      parts[#parts + 1] = "{\"name\":" .. json_quote(rr.name or "") .. ",\"type\":" .. tostring(rr.rtype) .. ",\"TTL\":" .. tostring(rr.ttl or 0) .. ",\"data\":" .. json_quote(rr_data_json rr) .. "}"
  parts[#parts + 1] = "]}"
  table.concat parts

-- ── TLS server helpers (mirrors auth/server.moon) ───────────────────────────

--- Create a listening IPv4 TCP socket on the given port.
-- @tparam number port TCP port.
-- @treturn table|nil Socket object, or nil + error string.
make_server4 = (port) ->
  srv = socket.tcp!
  srv\setoption "reuseaddr", true
  ok, err = srv\bind "0.0.0.0", port
  unless ok
    srv\close!
    return nil, err
  srv\listen 32
  srv\settimeout 1
  srv

--- Create a listening IPv6 TCP socket (non-fatal if IPv6 unavailable).
-- @tparam number port TCP port.
-- @treturn table|nil Socket object, or nil.
make_server6 = (port) ->
  ok6, srv6 = pcall socket.tcp6
  return nil unless ok6 and srv6
  srv6\setoption "reuseaddr", true
  srv6\setoption "ipv6-v6only", true
  ok62, _ = pcall srv6.bind, srv6, "::", port
  unless ok62
    srv6\close!
    return nil
  srv6\listen 32
  srv6\settimeout 1
  srv6

-- ── HTTP/2 minimal handler (RFC 7540 + RFC 8484 DoH) ─────────────────────────

H2_FRAME_DATA          = 0x0
H2_FRAME_HEADERS       = 0x1
H2_FRAME_SETTINGS      = 0x4
H2_FRAME_PING          = 0x6
H2_FRAME_GOAWAY        = 0x7
H2_FRAME_WINDOW_UPDATE = 0x8

H2_FLAG_END_STREAM     = 0x1
H2_FLAG_END_HEADERS    = 0x4
H2_FLAG_ACK            = 0x1

h2_recv_exact = (conn, n) ->
  buf = ""
  while #buf < n
    chunk, err = conn\receive n - #buf
    return nil, err unless chunk and #chunk > 0
    buf ..= chunk
  buf

h2_read_frame = (conn) ->
  hdr, err = h2_recv_exact conn, 9
  return nil, err unless hdr
  len   = hdr\byte(1) * 65536 + hdr\byte(2) * 256 + hdr\byte(3)
  ftype = hdr\byte(4)
  flags = hdr\byte(5)
  sid   = bit.band(
    bit.bor(
      bit.lshift(hdr\byte(6), 24),
      bit.lshift(hdr\byte(7), 16),
      bit.lshift(hdr\byte(8),  8),
      hdr\byte(9)
    ),
    0x7FFFFFFF
  )
  payload = if len > 0
    p, perr = h2_recv_exact conn, len
    return nil, perr unless p
    p
  else
    ""
  ftype, flags, sid, payload

h2_write_frame = (conn, ftype, flags, sid, payload) ->
  payload = payload or ""
  n = #payload
  frame = string.char(
    bit.band(bit.rshift(n, 16), 0xFF),
    bit.band(bit.rshift(n,  8), 0xFF),
    bit.band(n,                 0xFF),
    ftype, flags,
    bit.band(bit.rshift(sid, 24), 0xFF),
    bit.band(bit.rshift(sid, 16), 0xFF),
    bit.band(bit.rshift(sid,  8), 0xFF),
    bit.band(sid,                 0xFF)
  ) .. payload
  conn\send frame

-- HPACK : :status: 200 (index 8 = 0x88) + content-type: application/dns-message
-- (content-type = static index 31, literal with incremental indexing: 0x5f)
h2_encode_response_headers = ->
  "\x88\x5f\x17application/dns-message"

handle_h2 = (conn, peer_ip, peer_mac, upstream) ->
  -- Consomme la fin de la préface : "SM\r\n\r\n" (read_request a déjà lu "PRI * HTTP/2.0\r\n\r\n")
  conn\receive "*l"  -- "SM"
  conn\receive "*l"  -- "" (ligne vide)

  -- Préface serveur : SETTINGS vide
  h2_write_frame conn, H2_FRAME_SETTINGS, 0, 0, ""

  stream_id  = nil
  dns_chunks = {}
  done       = false

  for _ = 1, 30
    ftype, flags, sid, payload = h2_read_frame conn
    break unless ftype

    if ftype == H2_FRAME_SETTINGS and bit.band(flags, H2_FLAG_ACK) == 0
      h2_write_frame conn, H2_FRAME_SETTINGS, H2_FLAG_ACK, 0, ""

    elseif ftype == H2_FRAME_HEADERS and not stream_id
      stream_id = sid

    elseif ftype == H2_FRAME_DATA and sid == stream_id
      dns_chunks[#dns_chunks + 1] = payload if #payload > 0
      if bit.band(flags, H2_FLAG_END_STREAM) ~= 0
        done = true
        break

    elseif ftype == H2_FRAME_PING and bit.band(flags, H2_FLAG_ACK) == 0
      h2_write_frame conn, H2_FRAME_PING, H2_FLAG_ACK, 0, payload

  unless done and stream_id
    h2_write_frame conn, H2_FRAME_GOAWAY, 0, 0, "\x00\x00\x00\x00\x00\x00\x00\x01"
    return nil, "h2_incomplete"

  dns_raw = table.concat dns_chunks
  unless #dns_raw > 0
    h2_write_frame conn, H2_FRAME_GOAWAY, 0, 0, "\x00\x00\x00\x00\x00\x00\x00\x01"
    return nil, "h2_empty_body"

  resp_raw, q_err = process_query dns_raw, peer_ip, peer_mac, upstream
  unless resp_raw
    log_warn -> { action: "h2_query_error", peer: peer_ip, err: q_err }
    h2_write_frame conn, H2_FRAME_GOAWAY, 0, 0, "\x00\x00\x00\x00\x00\x00\x00\x02"
    return nil, "h2_query_error"

  hpack = h2_encode_response_headers!
  h2_write_frame conn, H2_FRAME_HEADERS, H2_FLAG_END_HEADERS, stream_id, hpack
  h2_write_frame conn, H2_FRAME_DATA, H2_FLAG_END_STREAM, stream_id, resp_raw
  h2_write_frame conn, H2_FRAME_GOAWAY, 0, 0, "\x00\x00\x00\x00\x00\x00\x00\x00"
  resp_raw

-- ── Per-connection child ─────────────────────────────────────────────────────

--- Handle a single DoH connection inside a forked child process.
-- @tparam table args {client, peer_ip, state}
handle_doh_client = (args) ->
  client   = args.client
  state    = args.state
  peer_ip  = args.peer_ip or "unknown"

  ok, err = pcall ->
    local_ip = client\getsockname! or "custos-doh"

    -- Load TLS certificate (same strategy as auth/server.moon).
    tls_ctx = nil
    if state.static_cert_paths
      ctx, ctx_err = load_static state.static_cert_paths.key, state.static_cert_paths.cert
      if ctx
        tls_ctx = ctx
      else
        log_error -> { action: "static_cert_child_failed", err: ctx_err }
        error "Cannot load static cert: #{ctx_err}"
    else
      ok_c, ctx_or_err = pcall -> load_or_generate_sni local_ip, state.cert_cache
      unless ok_c
        log_error -> { action: "cert_gen_failed", local_ip: local_ip, err: ctx_or_err }
        error "Cannot generate cert: #{ctx_or_err}"
      tls_ctx = ctx_or_err

    unless tls_ctx
      cert_type = if state.static_cert_paths then "static" else "sni"
      log_error -> { action: "cert_null", local_ip: local_ip, cert_type: cert_type }
      error "Certificate context is nil"

    client\settimeout nil   -- blocking for TLS handshake
    tls_client, tls_err = ssl.wrap client, tls_ctx
    unless tls_client
      log_warn -> { action: "tls_wrap_failed", peer: peer_ip, err: tls_err }
      client\close!
      return

    -- TLS handshake loop.
    done = false
    attempts = 0
    hs_err = nil
    while not done and attempts < 50
      attempts += 1
      ok_hs, hs_ret, hs_ret2 = pcall -> tls_client\dohandshake!
      if not ok_hs
        hs_err = tostring hs_ret
        log_warn -> { action: "handshake_error", peer: peer_ip, attempts: attempts, err: hs_err }
        break
      if hs_ret
        done = true
      elseif hs_ret2  -- erreur fatale (tls_error, peer_closed) : pas de retry
        hs_err = hs_ret2
        break

    unless done
      log_warn -> { action: "handshake_failed", peer: peer_ip, attempts: attempts, err: hs_err or "max_attempts" }
      tls_client\close!
      return

    selected_alpn = if tls_client.selected_alpn then tls_client\selected_alpn! else nil
    log_debug -> { action: "tls_handshake_ok", peer: peer_ip, attempts: attempts, alpn: selected_alpn or "none" }
    if selected_alpn == "h2"
      log_warn -> { action: "http2_not_supported", peer: peer_ip }
      tls_client\close!
      return
    peer_mac = get_mac peer_ip
    log_debug -> { action: "mac_lookup", peer: peer_ip, mac: peer_mac or "unknown" }

    req, req_err = read_request tls_client
    unless req
      log_warn -> { action: "request_read_failed", peer: peer_ip, err: req_err }
      tls_client\close!
      return

    -- ── Route /dns-query ────────────────────────────────────────────────────
    log_debug -> { action: "request", peer: peer_ip, method: req.method, path: req.path }

    -- Préambule HTTP/2 sans ALPN : traiter la connexion en HTTP/2 minimal.
    if req.method == "PRI"
      log_debug -> { action: "h2_request", peer: peer_ip }
      h2_resp, h2_err = handle_h2 tls_client, peer_ip, peer_mac, state.upstream
      if h2_err
        log_warn -> { action: "h2_failed", peer: peer_ip, err: h2_err }
      else
        log_debug -> { action: "h2_ok", peer: peer_ip, resp_bytes: h2_resp and #h2_resp or 0 }
      tls_client\close!
      return

    dns_raw = nil
    json_mode = false
    if req.path == "/dns-query" or req.path\match "^/dns%-query%?"
      ct = req.headers["content-type"] or ""
      accept = req.headers["accept"] or ""
      if req.method == "POST" and ct\match "application/dns%-message"
        log_debug -> { action: "post", peer: peer_ip, body_bytes: #req.body }
        dns_raw = req.body
      elseif req.method == "GET"
        dns_param = req.path\match "[?&]dns=([^&]+)"
        if dns_param
          dns_raw = b64url_decode dns_param
          log_debug -> { action: "get", peer: peer_ip, decoded_bytes: #dns_raw }
        elseif accept\match "application/dns%-json"
          name = query_param req.path, "name"
          qtype = qtype_from_name query_param req.path, "type"
          dns_raw = build_dns_query name, qtype
          json_mode = true if dns_raw
          log_debug -> { action: "get_json", peer: peer_ip, name: name or "", qtype: qtype, query_bytes: dns_raw and #dns_raw or 0 }
        else
          log_debug -> { action: "get_no_param", peer: peer_ip, path: req.path }
      else
        log_debug -> { action: "unsupported_method", peer: peer_ip, method: req.method, ct: ct }
        send_response tls_client, 415, {}, "Unsupported Media Type"
        tls_client\close!
        return
    else
      log_debug -> { action: "unknown_path", peer: peer_ip, path: req.path }

    unless dns_raw and #dns_raw > 0
      log_debug -> { action: "bad_request", peer: peer_ip, path: req.path }
      send_response tls_client, 400, {}, "Bad Request"
      tls_client\close!
      return

    -- ── process_query: filter + upstream + nft ──────────────────────────────
    resp_raw, q_err = process_query dns_raw, peer_ip, peer_mac, state.upstream
    if resp_raw
      log_debug -> { action: "response_ok", peer: peer_ip, resp_bytes: #resp_raw }
      if json_mode
        json = dns_response_json resp_raw
        send_response tls_client, 200,
          { ["Content-Type"]: "application/dns-json" },
          json or "{\"Status\":2}"
      else
        send_response tls_client, 200,
          { ["Content-Type"]: "application/dns-message" },
          resp_raw
    else
      log_warn -> { action: "query_error", peer: peer_ip, err: q_err }
      send_response tls_client, 502, {}, "Bad Gateway"

    tls_client\close!

  unless ok
    log_error -> { action: "conn_failed", peer: peer_ip, err: tostring err }
    pcall -> client\close!

-- ── Worker entry point ───────────────────────────────────────────────────────

--- Start the DoH worker.
-- Exits immediately if DOH_ENABLED is not "1".
-- @tparam table doh_cfg Configuration table (see load_doh_cfg in main.moon).
-- @tparam table filter_data Filter data (rules, auth_cfg_cache, decision_cfg) from main.moon.
-- @treturn nil
run = (doh_cfg, filter_data) ->
  set_action_prefix "doh_"
  nft_q = require "nft_queue"
  nft_q.set_wfd doh_cfg.nft_wfd if doh_cfg.nft_wfd
  -- Configure le canal ACK bidirectionnel si le superviseur en a alloué un.
  nft_q.set_ack_rfd doh_cfg.ack_rfd, doh_cfg.worker_idx if doh_cfg.ack_rfd and doh_cfg.worker_idx != nil

  -- Initialize filter with data passed from main.moon
  if filter_data
    filter = require "filter"
    filter.rules = filter_data.rules
    filter.auth_cfg_cache = filter_data.auth_cfg_cache
    filter.decision_cfg = filter_data.decision_cfg
    -- Détecte les règles wildcard d'auth pour l'injection nft (cf. doh.query).
    { :set_wildcard_rules } = require "doh.query"
    set_wildcard_rules filter_data.rules and filter_data.rules.rules_metadata
  unless doh_cfg.enabled
    log_info -> { action: "worker_disabled" }
    return

  port         = doh_cfg.port
  upstream_ip  = doh_cfg.upstream_ip
  upstream_port = doh_cfg.upstream_port
  timeout_ms   = doh_cfg.timeout_ms

  log_info -> {
    action: "worker_start"
    port:          port
    upstream_ip:   upstream_ip
    upstream_port: upstream_port
  }

  -- Create the persistent UDP upstream socket (reconnected per-child after fork).
  -- The socket is stored in state so each child re-opens it after fork.
  -- (File descriptors are not shared across fork boundaries for UDP in this model.)

  -- Certificate cache (shared across children via COW fork).
  cert_cache_mod = require "auth.cert_cache"
  cert_cache = cert_cache_mod.create_cache 500, 7776000   -- 500 slots, 90-day TTL

  static_cert_paths = nil
  if doh_cfg.cert and doh_cfg.key
    log_info -> { action: "loading_static_cert", cert: doh_cfg.cert }
    ok, ctx = load_static doh_cfg.key, doh_cfg.cert
    if ok
      static_cert_paths = { cert: doh_cfg.cert, key: doh_cfg.key }
      log_info -> { action: "static_cert_loaded" }
    else
      log_warn -> { action: "static_cert_load_failed", cert: doh_cfg.cert, key: doh_cfg.key, err: ctx }

  listen4, err4 = make_server4 port
  error "DoH: cannot bind port #{port}: #{err4}" unless listen4
  listen6 = make_server6 port
  all_servers = { listen4 }
  all_servers[#all_servers + 1] = listen6 if listen6

  log_info -> {
    action: "server_listening"
    port:   port
    ipv4:   "0.0.0.0"
    ipv6:   listen6 and "::" or nil
  }

  state = {
    :cert_cache
    :static_cert_paths
    upstream_ip:   upstream_ip
    upstream_port: upstream_port
    timeout_ms:    timeout_ms
    -- upstream socket created per-child (after fork) — stored as config only
    upstream: nil   -- placeholder; each child opens its own socket
  }

  while true
    while true
      dead_pid = reap_one!
      break unless dead_pid and dead_pid > 0

    readable, _ = socket.select all_servers, nil, 0.1
    if readable
      for srv in *readable
        client = srv\accept!
        if client
          peer_ip = client\getpeername! or "unknown"

          conn_state = {
            cert_cache:        state.cert_cache
            static_cert_paths: state.static_cert_paths
            upstream_ip:       upstream_ip
            upstream_port:     upstream_port
            timeout_ms:        timeout_ms
          }
          conn_arg = { :client, :peer_ip, state: conn_state }

          child_fn = (args) ->
            up, up_err = upstream_mod.new_client args.state.upstream_ip, args.state.upstream_port, args.state.timeout_ms
            unless up
              log_warn -> { action: "upstream_socket_failed", peer: args.peer_ip, upstream_ip: args.state.upstream_ip, upstream_port: args.state.upstream_port, err: up_err }
              args.client\close!
              return
            args.state.upstream = up
            handle_doh_client args
            upstream_mod.close up

          pid = fork_child "DOH-conn", child_fn, conn_arg, { log_start: false }

          log_debug -> { action: "conn_started", pid: pid, peer: peer_ip }
          client\close!

{ :run, :b64url_decode, :query_param, :build_dns_query }
