--
-- SPDX-FileCopyrightText: (c) 2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Générateur de charge DNS bout-en-bout (UDP/FFI).
-- Encode des requêtes DNS A, les envoie à débit cible via un client UDP non
-- bloquant, corrèle les réponses par txid et agrège QPS, pertes et latences.
-- Le client UDP est injectable (`opts.client_factory`) pour permettre des tests
-- sans réseau réel.

ffi = require "ffi"
report = require "bench.report"

floor = math.floor
char  = string.char
concat = table.concat

--- Horloge murale en secondes (gettimeofday via FFI, repli sur os.clock).
_now = do
  ok = pcall ffi.cdef, [[
    struct bench_timeval { long tv_sec; long tv_usec; };
    int gettimeofday(struct bench_timeval *tv, void *tz);
  ]]
  if ok
    tv = ffi.new "struct bench_timeval"
    ->
      ffi.C.gettimeofday tv, nil
      tonumber(tv.tv_sec) + tonumber(tv.tv_usec) / 1e6
  else
    -> os.clock!

--- Encode une requête DNS A en format wire.
-- @tparam number txid Transaction ID (0..65535).
-- @tparam string qname FQDN, ex. "www.example.com".
-- @tparam ?number qtype Type de requête (défaut 1 = A).
-- @treturn string Octets bruts de la requête DNS.
encode_query = (txid, qname, qtype = 1) ->
  parts = {}
  -- En-tête : id, flags(RD=0x0100), qdcount=1, an=ns=ar=0.
  hi = floor txid / 256
  lo = txid % 256
  parts[#parts + 1] = char hi, lo, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  -- QNAME : suite de labels longueur-préfixés, terminée par 0x00.
  for label in qname\gmatch "[^.]+"
    parts[#parts + 1] = char #label
    parts[#parts + 1] = label
  parts[#parts + 1] = char 0
  -- QTYPE + QCLASS(IN=1).
  parts[#parts + 1] = char floor(qtype / 256), qtype % 256, 0x00, 0x01
  concat parts

-- ── Client UDP réel non bloquant ───────────────────────────────────────────
_real_client_factory = (target, port, timeout_ms = 2000) ->
  ->
    sock = require "lib.socket"
    { :C, :AF_INET, :AF_INET6, :SOCK_DGRAM, :htons } = sock
    is_v6 = target\find(":") != nil
    family = is_v6 and AF_INET6 or AF_INET
    fd = C.socket family, SOCK_DGRAM, 0
    error "socket() failed" if fd < 0
    if is_v6
      addr = ffi.new "struct sockaddr_in6"
      addr.sin6_family = AF_INET6
      addr.sin6_port = htons port
      C.inet_pton AF_INET6, target, addr.sin6_addr
      C.connect fd, ffi.cast("struct sockaddr*", addr), ffi.sizeof addr
    else
      addr = ffi.new "struct sockaddr_in"
      addr.sin_family = AF_INET
      addr.sin_port = htons port
      C.inet_pton AF_INET, target, addr.sin_addr
      C.connect fd, ffi.cast("struct sockaddr*", addr), ffi.sizeof addr
    -- Mode non bloquant : O_NONBLOCK via fcntl.
    pcall ffi.cdef, "int fcntl(int, int, ...);"
    F_SETFL, O_NONBLOCK = 4, 2048
    flags = C.fcntl fd, 3, 0   -- F_GETFL
    C.fcntl fd, F_SETFL, ffi.cast("int", flags + O_NONBLOCK)
    buf = ffi.new "uint8_t[?]", 2048
    {
      send: (raw) =>
        C.send(fd, raw, #raw, 0) >= 0
      poll_response: =>
        n = C.recv fd, buf, 2048, 0
        return nil if n <= 0
        ffi.string buf, n
      close: => C.close fd
    }

--- Lance une campagne de charge.
-- @tparam table opts
--   target, port      : cible DNS (mode réseau réel).
--   max_queries       : nombre total de requêtes à émettre.
--   duration          : durée max en secondes (0 = uniquement borné par max_queries).
--   rate              : débit cible en req/s (nil = au plus vite).
--   domains           : liste de FQDN à interroger (round-robin).
--   client_factory    : fonction renvoyant un client { send, poll_response, close }.
--   timeout_ms        : budget d'attente des réponses en fin de campagne.
--   now               : horloge injectable (tests).
-- @treturn table { qps, sent, received, dropped, timeouts, p50, p95, p99, ... }.
run = (opts = {}) ->
  domains = opts.domains or { "www.example.com" }
  max_queries = opts.max_queries or 1000
  duration = opts.duration or 0
  rate = opts.rate
  now = opts.now or _now
  timeout_ms = opts.timeout_ms or 1000
  factory = opts.client_factory or _real_client_factory opts.target, opts.port or 53, timeout_ms
  client = factory!

  send_ts = {}       -- txid → instant d'émission
  latencies = {}     -- en ms
  sent = 0
  received = 0
  txid = 0

  drain = ->
    raw = client\poll_response!
    while raw
      if #raw >= 2
        rid = raw\byte(1) * 256 + raw\byte(2)
        if ts = send_ts[rid]
          latencies[#latencies + 1] = (now! - ts) * 1000
          send_ts[rid] = nil
          received += 1
      raw = client\poll_response!

  t_start = now!
  next_send = t_start
  while sent < max_queries
    break if duration > 0 and (now! - t_start) >= duration
    if rate
      -- Régulation simple : attend l'échéance de la prochaine émission.
      while now! < next_send
        drain!
      next_send += 1 / rate
    txid = (txid % 65535) + 1
    qname = domains[(sent % #domains) + 1]
    if client\send encode_query txid, qname
      send_ts[txid] = now!
      sent += 1
    drain!

  -- Phase de drainage final, bornée par timeout_ms.
  deadline = now! + timeout_ms / 1000
  while received < sent and now! < deadline
    drain!

  client\close!

  t_total = math.max now! - t_start, 1e-9
  pct = report.percentiles latencies
  dropped = sent - received
  {
    sent: sent
    received: received
    dropped: dropped
    timeouts: dropped
    qps: sent / t_total
    duration_s: t_total
    p50: pct.p50
    p95: pct.p95
    p99: pct.p99
    min: pct.min
    max: pct.max
  }

{ :encode_query, :run, :_real_client_factory }
