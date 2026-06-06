-- src/doh/upstream_doh.moon
-- Client upstream DNS-over-HTTPS pour le worker DoH.
-- Contrat identique à doh.upstream (new_client / query / close) afin que
-- doh.query puisse basculer de transport sans changer de logique métier.
-- Chaque appel new_client ouvre une connexion TCP + TLS et effectue le handshake.
-- Le handle porte un champ _mod pour le dispatch polymorphe dans doh.query.

ffi    = require "ffi"
ssl    = require "auth.ffi_wolfssl"
socket = require "lib.socket"
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

-- Analyse une URL "https://host[:port]/path".
-- @treturn string host, number port, string path — ou nil,nil,nil si invalide.
parse_url = (url) ->
  host, port_str, path = url\match "^https://([^/:]+):(%d+)(/.+)$"
  return host, tonumber(port_str), path if host
  host, path = url\match "^https://([^/]+)(/.+)$"
  return host, 443, path if host
  host = url\match "^https://([^/]+)$"
  return host, 443, "/dns-query" if host
  nil, nil, nil

set_timeouts = (fd, timeout_ms) ->
  tv = ffi.new "struct timeval"
  tv.tv_sec  = math.floor timeout_ms / 1000
  tv.tv_usec = (timeout_ms % 1000) * 1000
  C.setsockopt fd, SOL_SOCKET, SO_RCVTIMEO, tv, ffi.sizeof tv
  C.setsockopt fd, SOL_SOCKET, SO_SNDTIMEO, tv, ffi.sizeof tv

--- Ouvre une connexion TLS vers le résolveur DoH et retourne un handle.
-- @tparam string url        URL du résolveur, ex. "https://1.1.1.1/dns-query".
-- @tparam number timeout_ms Délai d'I/O en ms (défaut 2000).
-- @tparam bool   verify_tls Vérification du certificat serveur (défaut false).
-- @treturn table|nil  Handle {tls, host, path, _mod}, ou nil + erreur.
new_client = (url, timeout_ms=2000, verify_tls=false) ->
  host, port, path = parse_url url
  unless host
    return nil, "upstream_doh: invalid_url: #{url}"

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

  ctx = ssl.newclient_context { verify_peer: verify_tls }
  tls = ssl.wrap sock, ctx

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
    return nil, "upstream_doh: tls_handshake_failed: #{tls_err or 'max_attempts'}"

  log_debug -> { action: "upstream_doh_connected", :host, :port, :path }
  { :tls, :host, :path, _mod: M }

--- Envoie une requête DNS en HTTP POST et retourne la réponse brute.
-- @tparam table  client  Handle retourné par new_client().
-- @tparam string dns_raw Requête DNS wire format.
-- @treturn string|nil Réponse DNS brute, ou nil + erreur.
query = (client, dns_raw) ->
  tls  = client.tls
  host = client.host
  path = client.path

  req = table.concat {
    "POST ", path, " HTTP/1.1\r\n"
    "Host: ", host, "\r\n"
    "Content-Type: application/dns-message\r\n"
    "Accept: application/dns-message\r\n"
    "Content-Length: ", tostring(#dns_raw), "\r\n"
    "Connection: close\r\n"
    "\r\n"
    dns_raw
  }

  ok_send, send_err = pcall -> tls\send req
  unless ok_send
    return nil, "upstream_doh: send_failed: #{send_err}"

  -- Accumule la réponse HTTP (les réponses DoH tiennent en quelques paquets)
  chunks = {}
  content_length = nil

  for _ = 1, 20
    chunk = nil
    for _ = 1, 50
      c, recv_err = tls\receive 4096
      if c
        chunk = c
        break
      break if recv_err != "want_read_write"
    break unless chunk
    chunks[#chunks + 1] = chunk
    buf = table.concat chunks
    hdr_end = buf\find "\r\n\r\n", 1, true
    if hdr_end
      cl = tonumber buf\match "[Cc]ontent%-[Ll]ength:%s*(%d+)"
      content_length = cl
      body_len = #buf - hdr_end - 3
      break if not cl or body_len >= cl

  buf = table.concat chunks
  unless #buf > 0
    return nil, "upstream_doh: empty_response"

  status = tonumber buf\match "^HTTP/%d%.%d%s+(%d+)"
  unless status
    return nil, "upstream_doh: invalid_http_response"
  unless status == 200
    return nil, "upstream_doh: http_status_#{status}"

  hdr_end = buf\find "\r\n\r\n", 1, true
  return nil, "upstream_doh: no_headers_end" unless hdr_end

  body = buf\sub hdr_end + 4
  body = body\sub 1, content_length if content_length and content_length < #body

  log_debug -> { action: "upstream_doh_response", host: client.host, body_bytes: #body }
  body

--- Ferme la connexion TLS.
-- @tparam table client Handle retourné par new_client().
close = (client) ->
  client.tls\close! if client and client.tls and not client.tls.closed

M.new_client = new_client
M.query      = query
M.close      = close

M
