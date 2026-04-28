-- src/auth/worker_conn.moon
-- Forké par server.moon pour chaque connexion HTTP entrante.
-- Communique avec le session_manager via IPC binaire (stdin/stdout).

socket = require "socket"
{ :log_info } = require "log"

-- ── Construction du message IPC binaire ────────────────────────

build_ipc_message = (type, ip, mac, body) ->
  -- Pad IPv4 vers IPv6 (12 octets de zéros + 4 octets IPv4)
  if #ip == 4
    ip = string.rep("\0", 12) .. ip

  -- Mac par défaut si inconnu
  if mac == "unknown"
    mac = string.rep "\xFF", 6

  body_len = #body
  -- Format: type(1 byte) + ip(16 bytes) + mac(6 bytes) + body_len(2 bytes big-endian)
  string.pack(">c16c6H2", type, ip, mac, body_len) .. body

-- ── Parsing de la réponse IPC ─────────────────────────────────

parse_ipc_response = (data) ->
  -- Header: status(2) + headers_len(2) + body_len(4)
  status = data\byte(1) * 256 + data\byte(2)
  headers_len = data\byte(3) * 256 + data\byte(4)
  body_len = data\byte(5) * 256 * 256 * 256 +
             data\byte(6) * 256 * 256 +
             data\byte(7) * 256 +
             data\byte(8)

  headers_str = if headers_len > 0 then data\sub(9, 8 + headers_len) else ""
  body_data = if body_len > 0 then data\sub(9 + headers_len, 8 + headers_len + body_len) else ""

  -- Parser les headers sérialisés
  headers = {}
  h_pos = 1
  while h_pos <= headers_len
    name_len = headers_str\byte h_pos
    h_pos = h_pos + 1
    name = headers_str\sub h_pos, h_pos + name_len - 1
    h_pos = h_pos + name_len

    value_len = headers_str\byte h_pos
    h_pos = h_pos + 1
    value = headers_str\sub h_pos, h_pos + value_len - 1
    h_pos = h_pos + value_len

    headers[name] = value

  status, headers, body_data

-- ── Gestion de la connexion client ─────────────────────────────

handle_connection = (client_sock, peer_ip, peer_mac) ->
  client_sock\settimeout 10

  req = client_sock\receive "*l"
  unless req
    client_sock\close!
    return

  method, path = req\match "^(%w+)%s+([^%s]+)%s+HTTP"
  unless method and path
    client_sock\send "HTTP/1.1 404 Not Found\r\nContent-Length: 12\r\n\r\n<h1>404</h1>"
    client_sock\close!
    return

  -- Lire les headers et le body
  body = ""
  content_length = 0

  while true
    line = client_sock\receive "*l"
    break unless line
    if line\lower!\match "^content%-length:%s*(%d+)$"
      content_length = tonumber line\match "%d+"
    if line == ""
      break

  if content_length > 0
    body = client_sock\receive content_length

  -- Déterminer le type IPC
  ipc_type = if path == "/login"
    0x01
  elseif path == "/ping"
    0x02
  elseif path == "/logout"
    0x03
  elseif path == "/register"
    0x04
  else
    client_sock\send "HTTP/1.1 404 Not Found\r\nContent-Length: 12\r\n\r\n<h1>404</h1>"
    client_sock\close!
    return

  ipc_msg = build_ipc_message ipc_type, peer_ip, peer_mac, body

  -- Envoyer au session_manager via stdout
  io.stdout\write ipc_msg
  io.stdout\flush!

  -- Recevoir la réponse via stdin
  response_data = io.stdin\read 8
  unless response_data
    client_sock\close!
    return

  status, headers, body_data = parse_ipc_response response_data

  -- Construire et envoyer la réponse HTTP
  http_response = "HTTP/1.1 " .. status .. " OK\r\n"
  for name, value in pairs headers
    http_response = http_response .. name .. ": " .. value .. "\r\n"
  http_response = http_response .. "\r\n" .. body_data

  client_sock\send http_response
  client_sock\close!

-- ── Point d'entrée ───────────────────────────────────────────

main = ->
  peer_ip = arg[1] or "unknown"
  peer_mac = arg[2] or "unknown"
  handle_connection io.stdin, peer_ip, peer_mac

main!
