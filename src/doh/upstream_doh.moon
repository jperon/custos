-- src/doh/upstream_doh.moon
-- Client upstream DNS-over-HTTPS pour le worker DoH.
-- Contrat identique à doh.upstream (new_client / query / close) afin que
-- doh.query puisse basculer de transport sans changer de logique métier.
-- Chaque appel new_client ouvre une connexion TCP + TLS et effectue le handshake.
-- Le handle porte un champ _mod pour le dispatch polymorphe dans doh.query.

ffi    = require "ffi"
bit    = require "bit"
ssl    = require "auth.ffi_wolfssl"
socket = require "lib.socket"
h2f    = require "doh.h2_frames"
hpack  = require "doh.hpack"
{ :log_debug, :log_warn } = require "log"
{ :C, :SOL_SOCKET, :SO_RCVTIMEO, :SO_SNDTIMEO } = socket
libc   = ffi.C   -- ffi.C pour les fonctions libc (getaddrinfo, inet_ntop…)

-- struct timeval peut déjà être défini par lib.socket ; pcall évite l'erreur.
pcall ffi.cdef, "struct timeval { long tv_sec; long tv_usec; };"

-- getaddrinfo pour résoudre les noms d'hôtes (pas seulement les IPs).
pcall ffi.cdef, [[
  struct addrinfo {
    int              ai_flags;
    int              ai_family;
    int              ai_socktype;
    int              ai_protocol;
    unsigned int     ai_addrlen;
    struct sockaddr *ai_addr;
    char            *ai_canonname;
    struct addrinfo *ai_next;
  };
  int  getaddrinfo(const char *node, const char *service,
                   const struct addrinfo *hints, struct addrinfo **res);
  void freeaddrinfo(struct addrinfo *res);
  const char *inet_ntop(int af, const void *src, char *dst, unsigned int size);
]]

AF_INET  = 2
AF_INET6 = 10

-- Bornes du client HTTP/1.1 de repli (RFC 1035 : 65535 octets max pour un
-- message DNS ; marge pour les en-têtes HTTP).
MAX_DNS_BODY       = 65535
MAX_RESPONSE_BYTES = MAX_DNS_BODY + 8192
MAX_SEND_ATTEMPTS  = 100
MAX_RECV_ATTEMPTS  = 100
MAX_RECV_ROUNDS    = 32

-- Client HTTP/2 (RFC 7540/7541) quand ALPN a négocié « h2 ». Le repli reste
-- HTTP/1.1 si ALPN est absent, refusé ou si le serveur choisit http/1.1.
H2_PREFACE           = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
H2_CLIENT_ALPN       = "h2,http/1.1"
H2_STREAM_ID         = 1
H2_MAX_FRAMES        = 256
H2_MAX_HEADER_BLOCK  = 65535
H2_MAX_CONTINUATIONS = 64
H2_MAX_TOTAL_BYTES   = MAX_RESPONSE_BYTES

-- Résout un nom d'hôte ou une adresse IP littérale en (ip_string, family).
-- Préfère IPv4 sauf si seule une adresse IPv6 est disponible.
resolve_host = (host) ->
  res = ffi.new "struct addrinfo*[1]"
  rc  = libc.getaddrinfo host, nil, nil, res
  if rc != 0
    return nil, nil, "getaddrinfo failed (rc=#{rc}) for #{host}"
  ip4, ip6 = nil, nil
  cur = res[0]
  while cur != nil
    buf = ffi.new "char[64]"
    if cur.ai_family == AF_INET and not ip4
      src = ffi.cast "uint8_t*", cur.ai_addr
      libc.inet_ntop AF_INET, src + 4, buf, 64
      ip4 = ffi.string buf
    elseif cur.ai_family == AF_INET6 and not ip6
      src = ffi.cast "uint8_t*", cur.ai_addr
      libc.inet_ntop AF_INET6, src + 8, buf, 64
      ip6 = ffi.string buf
    cur = cur.ai_next
  libc.freeaddrinfo res[0]
  if ip4
    return ip4, AF_INET
  if ip6
    return ip6, AF_INET6
  nil, nil, "no address found for #{host}"

-- Référence circulaire : M est rempli en fin de module et copié dans chaque handle.
M = {}

-- Analyse une URL "https://host[:port][/path]" (IPv6 littéral entre crochets).
-- @tparam string url URL du résolveur.
-- @treturn string|nil host Sans crochets (compatible getaddrinfo/SNI).
-- @treturn number|nil port Port (443 par défaut).
-- @treturn string|nil path Chemin ("/dns-query" par défaut).
parse_url = (url) ->
  rest = url\match "^https://(.+)$"
  return nil, nil, nil unless rest

  authority, path = rest\match "^([^/]+)(/.*)$"
  unless authority
    authority = rest
    path = "/dns-query"
  return nil, nil, nil if authority == ""

  host, port = nil, 443
  if authority\sub(1, 1) == "["
    -- IPv6 littéral RFC 3986 : [addr] ou [addr]:port, crochets retirés.
    host, after = authority\match "^%[([^%]]+)%](.*)$"
    return nil, nil, nil unless host and host != ""
    if after != ""
      port_str = after\match "^:(%d+)$"
      return nil, nil, nil unless port_str
      port = tonumber port_str
  else
    h, port_str = authority\match "^([^:]+):(%d+)$"
    if h
      host = h
      port = tonumber port_str
    else
      -- IPv6 nue (non conforme RFC 3986 mais tolérée) ou nom d'hôte simple.
      host = authority

  return nil, nil, nil unless host and #host > 0
  return nil, nil, nil unless port and port >= 1 and port <= 65535
  host, port, path

--- Formate l'en-tête Host (crochets autour d'une IPv6, port si non standard).
-- @tparam string host Hôte sans crochets.
-- @tparam number port Port effectif.
-- @treturn string Valeur de l'en-tête Host.
format_host_header = (host, port) ->
  h = if host\find ":", 1, true then "[#{host}]" else host
  if port != 443 then "#{h}:#{port}" else h

set_timeouts = (fd, timeout_ms) ->
  tv = ffi.new "struct timeval"
  tv.tv_sec  = math.floor timeout_ms / 1000
  tv.tv_usec = (timeout_ms % 1000) * 1000
  C.setsockopt fd, SOL_SOCKET, SO_RCVTIMEO, tv, ffi.sizeof tv
  C.setsockopt fd, SOL_SOCKET, SO_SNDTIMEO, tv, ffi.sizeof tv

--- Indique si un hôte est une IP littérale (pas d'IP dans SNI, RFC 6066).
-- @tparam string host Nom d'hôte ou IP.
-- @treturn boolean true pour une IPv4 pointée ou une IPv6 (contient ':').
is_ip_literal = (host) ->
  return true if host\find ":", 1, true
  host\match("^%d+%.%d+%.%d+%.%d+$") != nil

--- Ouvre une connexion TLS vers le résolveur DoH et retourne un handle.
-- @tparam string url        URL du résolveur, ex. "https://1.1.1.1/dns-query".
-- @tparam number timeout_ms Délai d'I/O en ms (défaut 2000).
-- @tparam bool   verify_tls Vérification du certificat serveur (défaut false).
-- @tparam table  opts       Options {ca_file: string|nil}.
-- @treturn table|nil  Handle {tls, host, path, ctx, _mod}, ou nil + erreur.
new_client = (url, timeout_ms=2000, verify_tls=false, opts={}) ->
  host, port, path = parse_url url
  unless host
    return nil, "upstream_doh: invalid_url: #{url}"

  ca_file = nil
  if verify_tls
    unless type(ssl.verification_available) == "function"
      return nil, "upstream_doh: tls_verify_unavailable: module wolfSSL sans sonde"
    available, why, ca = ssl.verification_available { ca_file: opts.ca_file }
    unless available
      return nil, "upstream_doh: tls_verify_unavailable: #{why}"
    ca_file = ca

  ip, family, r_err = resolve_host host
  unless ip
    return nil, "upstream_doh: resolve_failed: #{r_err}"

  ok_s, sock = pcall (if family == AF_INET6 then socket.create_tcp6 else socket.create_tcp)
  unless ok_s
    return nil, "upstream_doh: socket_create_failed: #{sock}"

  set_timeouts sock.fd, timeout_ms

  ok_c, c_err = pcall -> sock\connect ip, port
  unless ok_c
    sock\close!
    return nil, "upstream_doh: connect_failed: #{c_err}"

  ok_ctx, ctx = pcall ssl.newclient_context, { verify_peer: verify_tls, ca_file: ca_file }
  unless ok_ctx
    sock\close!
    return nil, "upstream_doh: tls_context_failed: #{ctx}"

  -- SNI seulement pour un nom d'hôte ; contrôle du nom (SAN/CN) si vérifié.
  sni = if verify_tls and not is_ip_literal(host) then host else nil
  ok_wrap, tls = pcall ssl.wrap, sock, ctx, {
    sni: sni
    check_domain: verify_tls and host or nil
    -- Opt-in ALPN client : h2 d'abord, HTTP/1.1 sinon. Sur une libwolfssl
    -- sans ALPN (ou un refus), le wrap réussit quand même et le protocole
    -- négocié reste nil → chemin HTTP/1.1 inchangé.
    alpn_protocols: H2_CLIENT_ALPN
  }
  unless ok_wrap
    ssl.free_context ctx
    sock\close!
    return nil, "upstream_doh: tls_wrap_failed: #{tls}"

  -- Handshake TLS client (boucle pour WANT_READ/WANT_WRITE sur socket bloquant)
  done = false
  tls_err = nil
  for _ = 1, 50
    ok_hs, hs_ret, hs_err = pcall -> tls\doconnect!
    unless ok_hs
      tls_err = tostring hs_ret
      break
    if hs_ret
      done = true
      break
    if hs_err
      tls_err = hs_err
      break

  unless done
    tls\close!
    ssl.free_context ctx
    return nil, "upstream_doh: tls_handshake_failed: #{tls_err or 'max_attempts'}"

  -- Protocole ALPN réellement négocié (h2 ou http/1.1), si exposé par le
  -- wrapper TLS. Toute absence/erreur laisse le comportement HTTP/1.1.
  alpn = nil
  if type(tls.selected_alpn) == "function"
    ok_alpn, sel = pcall -> tls\selected_alpn!
    alpn = sel if ok_alpn and type(sel) == "string" and #sel > 0

  log_debug -> { action: "upstream_doh_connected", :host, :port, :path, :alpn }
  {
    :tls, :host, :port, :path, :ctx, :alpn
    h2: alpn == "h2"
    host_header: format_host_header(host, port)
    _mod: M
  }

--- Écrit toutes les données sur la connexion TLS, écritures partielles incluses.
-- @tparam table tls Wrapper TLS (auth.ffi_wolfssl).
-- @tparam string data Données à écrire.
-- @treturn boolean|nil true si tout a été écrit.
-- @treturn string|nil Raison de l'échec.
send_all = (tls, data) ->
  total = #data
  sent  = 0
  attempts = 0
  while sent < total
    n = tls\send data\sub(sent + 1)
    if n and n > 0
      sent += n
      attempts = 0
    else
      attempts += 1
      return nil, "send_timeout" if attempts > MAX_SEND_ATTEMPTS
  true

--- Lit un fragment de réponse, en absorbant WANT_READ/WANT_WRITE.
-- @tparam table tls Wrapper TLS.
-- @treturn string|nil Fragment reçu.
-- @treturn string|nil "eof" (fermeture propre), erreur, ou nil si fragment.
recv_some = (tls) ->
  for _ = 1, MAX_RECV_ATTEMPTS
    chunk, err = tls\receive 4096
    return chunk if chunk
    return nil, "eof" if err == "eof_from_peer"
    return nil, err unless err == "want_read_write"
  nil, "recv_timeout"

--- Accumule une réponse HTTP/1.1 bornée (corps ≤ MAX_DNS_BODY).
-- @tparam table tls Wrapper TLS.
-- @treturn string|nil Réponse brute complète.
-- @treturn string|nil Raison de l'échec.
read_response = (tls) ->
  chunks = {}
  total = 0
  content_length = nil
  hdr_end = nil

  for _ = 1, MAX_RECV_ROUNDS
    chunk, err = recv_some tls
    unless chunk
      break if err == "eof"
      return nil, err
    total += #chunk
    return nil, "response_too_large" if total > MAX_RESPONSE_BYTES
    chunks[#chunks + 1] = chunk
    buf = table.concat chunks
    hdr_end or= buf\find "\r\n\r\n", 1, true
    if hdr_end
      cl = tonumber buf\match "[Cc]ontent%-[Ll]ength:%s*(%d+)"
      if cl
        return nil, "content_length_too_large" if cl > MAX_DNS_BODY
        content_length = cl
        body_len = #buf - hdr_end - 3
        return buf if body_len >= cl

  buf = table.concat chunks
  return nil, "empty_response" if #buf == 0
  hdr_end = buf\find "\r\n\r\n", 1, true
  return nil, "no_headers_end" unless hdr_end
  body_len = #buf - hdr_end - 3
  if content_length and body_len < content_length
    return nil, "truncated_body"
  buf

--- Envoie une frame HTTP/2 sur la connexion TLS du handle.
-- @tparam table  client Handle de new_client().
-- @tparam number ftype  Type de frame.
-- @tparam number flags  Flags.
-- @tparam number sid    Stream ID.
-- @tparam string payload Corps.
-- @treturn boolean|nil true, ou nil + raison.
h2_send = (client, ftype, flags, sid, payload) ->
  ok, sent, err = pcall h2f.h2_write_frame, client.tls, ftype, flags, sid, payload
  return nil, "send_failed: #{sent}" unless ok
  return nil, "send_failed: #{err}" unless sent
  true

--- Envoie le corps DNS en DATA, découpé à la taille de frame par défaut.
-- Un message DNS peut dépasser 16384 octets (EDNS/TXT) : envoyer une seule
-- frame violerait SETTINGS_MAX_FRAME_SIZE du pair.
-- @tparam table  client  Handle.
-- @tparam string dns_raw Requête DNS wire.
-- @treturn boolean|nil true, ou nil + raison.
h2_send_body = (client, dns_raw) ->
  max = h2f.H2_DEFAULT_MAX_FRAME_SIZE
  pos = 1
  total = #dns_raw
  while true
    chunk = dns_raw\sub pos, pos + max - 1
    pos += #chunk
    last = pos > total
    flags = last and h2f.H2_FLAG_END_STREAM or 0
    ok, err = h2_send client, h2f.H2_FRAME_DATA, flags, H2_STREAM_ID, chunk
    return nil, err unless ok
    break if last
  true

--- Ferme la connexion après une erreur de protocole h2 (reconnexion au prochain
-- appel, comme le chemin HTTP/1.1).
-- @tparam table  client Handle.
-- @tparam string msg    Erreur à retourner.
-- @treturn nil, string
h2_fail = (client, msg) ->
  pcall -> M.close client
  nil, msg

--- Requête DoH en HTTP/2 : préface, SETTINGS, POST sur un flux impair, puis
-- lecture bornée des trames jusqu'à END_STREAM.
-- @tparam table  client   Handle dont `h2` est vrai.
-- @tparam string dns_raw  Requête DNS wire.
-- @tparam number req_txid TXID attendu dans la réponse.
-- @treturn string|nil Réponse DNS brute, ou nil + erreur.
query_h2 = (client, dns_raw, req_txid) ->
  ok_send, send_err = send_all client.tls, H2_PREFACE
  return nil, "upstream_doh: send_failed: #{send_err}" unless ok_send

  ok, err = h2_send client, h2f.H2_FRAME_SETTINGS, 0, 0, ""
  return h2_fail client, "upstream_doh: #{err}" unless ok

  block = hpack.encode {
    { ":method", "POST" }
    { ":scheme", "https" }
    { ":authority", client.host_header or client.host }
    { ":path", client.path }
    { "content-type", "application/dns-message" }
    { "accept", "application/dns-message" }
    { "content-length", tostring #dns_raw }
  }
  ok, err = h2_send client, h2f.H2_FRAME_HEADERS, h2f.H2_FLAG_END_HEADERS, H2_STREAM_ID, block
  return h2_fail client, "upstream_doh: #{err}" unless ok

  ok, err = h2_send_body client, dns_raw
  return h2_fail client, "upstream_doh: #{err}" unless ok

  decoder     = hpack.new_decoder!
  status      = nil
  body_chunks = {}
  body_len    = 0
  total_bytes = 0
  frame_count = 0
  end_stream  = false

  while not end_stream
    frame_count += 1
    return h2_fail client, "upstream_doh: h2_too_many_frames" if frame_count > H2_MAX_FRAMES

    ftype, fflags, sid, payload = h2f.h2_read_frame client.tls, h2f.H2_DEFAULT_MAX_FRAME_SIZE
    unless ftype
      return h2_fail client, "upstream_doh: h2_frame_read_#{fflags or 'failed'}"

    total_bytes += #payload + 9
    return h2_fail client, "upstream_doh: response_too_large" if total_bytes > H2_MAX_TOTAL_BYTES

    if ftype == h2f.H2_FRAME_SETTINGS
      unless sid == 0 and #payload % 6 == 0
        return h2_fail client, "upstream_doh: h2_bad_settings"
      if bit.band(fflags, h2f.H2_FLAG_ACK) == 0
        ok, err = h2_send client, h2f.H2_FRAME_SETTINGS, h2f.H2_FLAG_ACK, 0, ""
        return h2_fail client, "upstream_doh: #{err}" unless ok

    elseif ftype == h2f.H2_FRAME_PING
      unless sid == 0 and #payload == 8
        return h2_fail client, "upstream_doh: h2_bad_ping"
      if bit.band(fflags, h2f.H2_FLAG_ACK) == 0
        ok, err = h2_send client, h2f.H2_FRAME_PING, h2f.H2_FLAG_ACK, 0, payload
        return h2_fail client, "upstream_doh: #{err}" unless ok

    elseif ftype == h2f.H2_FRAME_HEADERS
      return h2_fail client, "upstream_doh: h2_unexpected_stream" unless sid == H2_STREAM_ID
      hblock, hs_end, header_err = h2f.h2_read_header_block client.tls, sid, fflags,
        payload, H2_MAX_HEADER_BLOCK, H2_MAX_CONTINUATIONS
      unless hblock
        return h2_fail client, "upstream_doh: #{header_err or 'h2_headers_invalid'}"
      headers, dec_err = hpack.decode decoder, hblock
      return h2_fail client, "upstream_doh: h2_hpack_#{dec_err}" unless headers
      st = hpack.header_value headers, ":status"
      if st
        -- Un second :status est invalide ; les en-têtes sans :status après la
        -- réponse sont des trailers (RFC 7540 §8.1), ignorés mais décodés.
        return h2_fail client, "upstream_doh: h2_duplicate_status" if status
        status = st
        unless status == "200"
          return h2_fail client, "upstream_doh: http_status_#{status}"
      elseif not status
        return h2_fail client, "upstream_doh: h2_missing_status"
      end_stream = hs_end

    elseif ftype == h2f.H2_FRAME_DATA
      return h2_fail client, "upstream_doh: h2_unexpected_stream" unless sid == H2_STREAM_ID
      content, data_err = h2f.h2_data_payload fflags, payload
      return h2_fail client, "upstream_doh: #{data_err or 'h2_data_invalid'}" unless content
      body_len += #content
      return h2_fail client, "upstream_doh: body_too_large" if body_len > MAX_DNS_BODY
      body_chunks[#body_chunks + 1] = content
      -- Rend au pair la fenêtre consommée (DATA est contrôlé en flux, padding inclus).
      if #payload > 0
        ok, err = h2f.h2_window_update client.tls, 0, #payload
        return h2_fail client, "upstream_doh: #{err or 'window_update_failed'}" unless ok
        ok, err = h2f.h2_window_update client.tls, sid, #payload
        return h2_fail client, "upstream_doh: #{err or 'window_update_failed'}" unless ok
      if bit.band(fflags, h2f.H2_FLAG_END_STREAM) != 0
        end_stream = true

    elseif ftype == h2f.H2_FRAME_RST_STREAM
      return h2_fail client, "upstream_doh: h2_rst_stream"

    elseif ftype == h2f.H2_FRAME_GOAWAY
      return h2_fail client, "upstream_doh: h2_goaway"
    -- WINDOW_UPDATE et types inconnus : ignorés, la boucle reste bornée.

  return h2_fail client, "upstream_doh: h2_missing_status" unless status == "200"

  body = table.concat body_chunks
  return h2_fail client, "upstream_doh: empty_body" if #body == 0
  return h2_fail client, "upstream_doh: short_response" if #body < 12

  resp_txid = body\byte(1) * 256 + body\byte(2)
  unless resp_txid == req_txid
    return h2_fail client, "upstream_doh: txid_mismatch"

  log_debug -> { action: "upstream_doh_response", host: client.host, body_bytes: #body, protocol: "h2" }
  body

--- Envoie une requête DNS en HTTP POST et retourne la réponse brute.
-- Corrèle la réponse au txid de la requête et borne taille/statut/troncature.
-- @tparam table  client  Handle retourné par new_client().
-- @tparam string dns_raw Requête DNS wire format.
-- @treturn string|nil Réponse DNS brute, ou nil + erreur.
query = (client, dns_raw) ->
  return nil, "upstream_doh: no_client" unless client and client.tls
  return nil, "upstream_doh: short_query" if #dns_raw < 12

  req_txid = dns_raw\byte(1) * 256 + dns_raw\byte(2)
  return query_h2 client, dns_raw, req_txid if client.h2

  req = table.concat {
    "POST ", client.path, " HTTP/1.1\r\n"
    "Host: ", client.host_header or client.host, "\r\n"
    "Content-Type: application/dns-message\r\n"
    "Accept: application/dns-message\r\n"
    "Content-Length: ", tostring(#dns_raw), "\r\n"
    "Connection: close\r\n"
    "\r\n"
    dns_raw
  }

  ok_send, send_ok, send_err = pcall send_all, client.tls, req
  unless ok_send
    return nil, "upstream_doh: send_failed: #{send_ok}"
  unless send_ok
    return nil, "upstream_doh: send_failed: #{send_err}"

  ok_recv, buf, recv_err = pcall read_response, client.tls
  unless ok_recv
    return nil, "upstream_doh: recv_failed: #{buf}"
  unless buf
    return nil, "upstream_doh: #{recv_err}"

  status = tonumber buf\match "^HTTP/%d%.%d%s+(%d+)"
  unless status
    return nil, "upstream_doh: invalid_http_response"
  unless status == 200
    return nil, "upstream_doh: http_status_#{status}"

  hdr_end = buf\find "\r\n\r\n", 1, true
  return nil, "upstream_doh: no_headers_end" unless hdr_end

  content_length = tonumber buf\match "[Cc]ontent%-[Ll]ength:%s*(%d+)"
  if content_length and content_length > MAX_DNS_BODY
    return nil, "upstream_doh: content_length_too_large"

  body = buf\sub hdr_end + 4
  if content_length
    return nil, "upstream_doh: truncated_body" if #body < content_length
    body = body\sub 1, content_length
  return nil, "upstream_doh: empty_body" if #body == 0
  return nil, "upstream_doh: short_response" if #body < 12

  resp_txid = body\byte(1) * 256 + body\byte(2)
  unless resp_txid == req_txid
    return nil, "upstream_doh: txid_mismatch"

  log_debug -> { action: "upstream_doh_response", host: client.host, body_bytes: #body }
  body

--- Ferme la connexion TLS.
-- @tparam table client Handle retourné par new_client().
close = (client) ->
  return unless client
  client.tls\close! if client.tls and not client.tls.closed
  if client.ctx
    ssl.free_context client.ctx
    client.ctx = nil

--- Vérifie que le repli peut vérifier certificat et nom d'hôte.
-- Délégué à auth.ffi_wolfssl : la sonde tient compte des symboles réellement
-- résolus par la libwolfssl chargée et d'un magasin de CA lisible.
-- @tparam table|nil opts {ca_file: string|nil}.
-- @treturn boolean Disponibilité.
-- @treturn string|nil Raison de l'indisponibilité.
-- @treturn string|nil Chemin du magasin de CA retenu.
verification_available = (opts={}) ->
  unless type(ssl.verification_available) == "function"
    return false, "module wolfSSL sans sonde de vérification", nil
  ssl.verification_available opts

M.new_client = new_client
M.query      = query
M.close      = close
M.parse_url  = parse_url
M.verification_available = verification_available

M
