-- src/auth/sni_peek.moon
-- Lecture du premier enregistrement TLS (ClientHello) SANS le consommer.
--
-- Le certificat dynamique du portail AUTH dépend du nom SNI, qu'il faut
-- connaître AVANT ssl.wrap/dohandshake. On observe donc le descripteur brut
-- avec recv(MSG_PEEK) : les octets restent dans la file et WolfSSL les relit
-- normalement. L'attente est bornée (select + MSG_DONTWAIT) pour ne jamais
-- dépasser le budget de handshake de l'appelant.

ffi = require "ffi"
{ :socket_select } = require "lib.socket"
{ :extract_sni } = require "auth.sni_extractor"

pcall ffi.cdef, "int recv(int sockfd, void *buf, unsigned long len, int flags);"

-- MSG_PEEK | MSG_DONTWAIT : ne consomme rien et ne bloque jamais ; l'attente
-- est faite par select, bornée par l'échéance passée par l'appelant.
PEEK_FLAGS = 66
TLS_RECORD_HEADER = 5
-- Un ClientHello tient largement dans 8 Kio. Au-delà, on s'arrête : le SNI
-- sera considéré comme absent et le certificat retombera sur l'IP locale.
PEEK_MAX_BYTES = 8192
DEFAULT_TIMEOUT = 15

--- Taille complète visée du premier enregistrement TLS, plafonnée.
-- @tparam string data Préfixe déjà observé
-- @treturn number|nil Taille en octets, nil si l'en-tête est illisible
record_target = (data) ->
  return nil unless data and #data >= TLS_RECORD_HEADER
  record_len = data\byte(4) * 256 + data\byte(5)
  return nil if record_len <= 0
  math.min TLS_RECORD_HEADER + record_len, PEEK_MAX_BYTES

--- Attend que le socket soit lisible dans le délai imparti.
-- @tparam table sock Socket (utilise `fd`)
-- @tparam number timeout Délai en secondes
-- @treturn boolean
wait_readable = (sock, timeout) ->
  fds = { sock }
  readable, _ = socket_select fds, nil, timeout
  readable and #readable > 0

--- recv(MSG_PEEK|MSG_DONTWAIT) : renvoie le préfixe disponible, sans consommer.
-- @tparam number fd Descripteur
-- @tparam number len Taille maximale demandée
-- @treturn string|nil Préfixe, ou nil si rien n'est disponible/erreur
peek_fd = (fd, len) ->
  buf = ffi.new "uint8_t[?]", len
  n = ffi.C.recv fd, buf, len, PEEK_FLAGS
  return nil if n <= 0
  ffi.string buf, n

--- Lit le premier enregistrement TLS sans le consommer.
-- Une seule observation ne suffit pas si le ClientHello est fragmenté : le
-- préfixe est réobservé (MSG_PEEK relit toujours depuis le début) jusqu'à la
-- taille annoncée par l'en-tête, au plafond PEEK_MAX_BYTES ou à l'échéance.
-- @tparam table sock Socket (utilise `fd`)
-- @tparam table opts { timeout, deadline, now_fn, wait_fn, peek_fn }
-- @treturn string|nil Préfixe lu (éventuellement partiel), nil si rien
read_client_hello = (sock, opts = {}) ->
  return nil unless sock and type(sock.fd) == "number"
  now_fn = opts.now_fn or os.time
  timeout = tonumber(opts.timeout) or DEFAULT_TIMEOUT
  timeout = DEFAULT_TIMEOUT if timeout <= 0
  deadline = opts.deadline or (now_fn! + timeout)
  wait_fn = opts.wait_fn or wait_readable
  peek_fn = opts.peek_fn or peek_fd

  data = ""
  while true
    target = if #data >= TLS_RECORD_HEADER then record_target(data) else TLS_RECORD_HEADER
    break unless target
    return data if #data >= target
    remaining = deadline - now_fn!
    break if remaining <= 0
    break unless wait_fn sock, remaining
    chunk = peek_fn sock.fd, target
    break unless chunk and #chunk > 0
    break if #chunk <= #data  -- pas de progression : ne jamais boucler à vide
    data = chunk

  return nil if #data == 0
  data

--- SNI du ClientHello en attente, sans le consommer.
-- Ne lève jamais : un ClientHello absent, tronqué ou malformé donne nil et
-- l'appelant retombe sur le certificat de l'IP locale.
-- @tparam table sock Socket (utilise `fd`)
-- @tparam table opts Options de read_client_hello
-- @treturn string|nil Nom SNI brut (non validé), ou nil
extract_client_sni = (sock, opts = {}) ->
  ok, sni = pcall ->
    data = read_client_hello sock, opts
    extract_sni data if data
  return nil unless ok
  sni or nil

{ :read_client_hello, :extract_client_sni, :record_target, :PEEK_MAX_BYTES }
