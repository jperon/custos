-- tests/unit/doh/upstream_spec.moon
-- Tests unitaires de doh.upstream (client UDP/53).
-- lib.socket est stubbé : aucune I/O réseau réelle, C.recv rejoue un script.

ffi = require "ffi"
pcall ffi.cdef, [[int* __errno_location(void);]]
pcall ffi.cdef, [[struct sockaddr { unsigned short sa_family; char sa_data[14]; };]]
pcall ffi.cdef, [[struct timeval { long tv_sec; long tv_usec; };]]
pcall ffi.cdef, [[struct sockaddr_in { unsigned short sin_family; unsigned short sin_port; unsigned char sin_addr[4]; unsigned char sin_zero[8]; };]]
pcall ffi.cdef, [[struct sockaddr_in6 { unsigned short sin6_family; unsigned short sin6_port; unsigned int sin6_flowinfo; unsigned char sin6_addr[16]; unsigned int sin6_scope_id; };]]
sp = require("ipparse.lib.pack_compat").pack

eval_log = (f) -> (type(f) == "function") and f!
package.loaded["log"] = {
  log_warn: eval_log, log_debug: eval_log, log_info: eval_log
}

-- Script C.recv : chaque entrée est soit une string (datagramme), soit
-- { "error", errno } (échec équivalent à un timeout SO_RCVTIMEO).
-- opts permet de scripter les autres appels C (socket, inet_pton, connect,
-- send) pour exercer les branches d'erreur.
make_socket_stub = (recv_script, opts={}) ->
  state = { sent: {}, recv_calls: 0, closed: false, setsockopt_calls: {} }
  mod = {
    C: {
      socket: ->
        if opts.socket_fail
          ffi.C.__errno_location()[0] = opts.errno or 11
          return -1
        42
      close: (fd) -> state.closed = true
      setsockopt: (fd, level, opt, val, len) ->
        state.setsockopt_calls[#state.setsockopt_calls + 1] = {
          opt: opt, sec: tonumber(val.tv_sec), usec: tonumber(val.tv_usec)
        }
        0
      inet_pton: (af, src, dst) ->
        if opts.inet_pton != nil then opts.inet_pton else 1
      connect: (fd, addr, len) ->
        if opts.connect != nil
          if opts.connect < 0
            ffi.C.__errno_location()[0] = opts.errno or 101
          return opts.connect
        0
      send: (fd, data, len, flags) ->
        if opts.send_fail
          ffi.C.__errno_location()[0] = opts.errno or 32
          return -1
        state.sent[#state.sent + 1] = ffi.string data, len
        len
      recv: (fd, buf, size, flags) ->
        state.recv_calls += 1
        step = recv_script[math.min state.recv_calls, #recv_script]
        if type(step) == "string"
          ffi.copy buf, step, #step
          #step
        elseif step and step[1] == "error"
          ffi.C.__errno_location()[0] = step[2]
          -1
        else
          0
    }
    AF_INET: 2
    AF_INET6: 10
    SOCK_DGRAM: 2
    SOL_SOCKET: 1
    SO_RCVTIMEO: 20
    SO_SNDTIMEO: 21
    htons: (x) -> x
    _state: state
  }
  mod

load_mod = (recv_script, opts={}) ->
  socket_stub = make_socket_stub recv_script, opts
  package.loaded["lib.socket"] = socket_stub
  package.loaded["doh.upstream"] = nil
  { require("doh.upstream"), socket_stub._state }

-- Requête DNS minimale (txid + flags QR=0 + counts).
make_query = (txid=0x1234) -> sp ">H H H H H H", txid, 0x0100, 1, 0, 0, 0
-- Réponse DNS minimale (QR=1).
make_response = (txid=0x1234) -> sp ">H H H H H H", txid, 0x8180, 1, 1, 0, 0

describe "doh.upstream", ->

  describe "new_client / close", ->
    it "crée un handle connecté et le ferme", ->
      { mod, state } = load_mod {}
      client, err = mod.new_client "127.0.0.1", 53, 2000
      assert.is_nil err
      assert.equals 42, client.fd
      assert.equals 2000, client.timeout_ms
      mod.close client
      assert.is_true state.closed

  describe "query — corrélation du txid", ->

    it "rend une réponse dont le txid correspond", ->
      { mod } = load_mod { make_response 0x1234 }
      client = mod.new_client "127.0.0.1", 53, 2000
      resp, err = mod.query client, make_query 0x1234
      assert.is_nil err
      assert.equals make_response(0x1234), resp

    it "ignore un mauvais txid puis rend la bonne réponse", ->
      { mod } = load_mod { make_response(0xBEEF), make_response 0x1234 }
      client = mod.new_client "127.0.0.1", 53, 2000
      resp, err = mod.query client, make_query 0x1234
      assert.is_nil err
      assert.equals make_response(0x1234), resp

    it "ignore un datagramme de moins de 12 octets", ->
      { mod } = load_mod { "\0\1\2\3\4", make_response 0x1234 }
      client = mod.new_client "127.0.0.1", 53, 2000
      resp, err = mod.query client, make_query 0x1234
      assert.is_nil err
      assert.equals make_response(0x1234), resp

    it "ignore une requête renvoyée en écho (QR=0)", ->
      { mod } = load_mod { make_query(0x1234), make_response 0x1234 }
      client = mod.new_client "127.0.0.1", 53, 2000
      resp, err = mod.query client, make_query 0x1234
      assert.is_nil err
      assert.equals make_response(0x1234), resp

    it "échoue après 8 datagrammes ignorés", ->
      script = {}
      for _ = 1, 8
        script[#script + 1] = make_response 0xBEEF
      { mod } = load_mod script
      client = mod.new_client "127.0.0.1", 53, 60000
      resp, err = mod.query client, make_query 0x1234
      assert.is_nil resp
      assert.equals "no matching response (txid)", err

    it "échoue dès l'échéance du client dépassée", ->
      { mod } = load_mod { make_response 0xBEEF, make_response 0x1234 }
      client = mod.new_client "127.0.0.1", 53, 0
      resp, err = mod.query client, make_query 0x1234
      assert.is_nil resp
      assert.equals "no matching response (txid)", err

    it "rend nil + message sur timeout sans réponse", ->
      { mod } = load_mod { { "error", 11 } }
      client = mod.new_client "127.0.0.1", 53, 2000
      resp, err = mod.query client, make_query 0x1234
      assert.is_nil resp
      assert.truthy err\find "recv() timed out or failed", 1, true

describe "doh.upstream — familles et timeouts", ->

  it "détecte IPv6 et applique SO_RCVTIMEO/SO_SNDTIMEO", ->
    { mod, state } = load_mod {}
    client, err = mod.new_client "::1", 53, 1500
    assert.is_nil err
    assert.equals 10, client.family
    assert.equals "::1", client.upstream_ip
    assert.equals 2, #state.setsockopt_calls
    for call in *state.setsockopt_calls
      assert.equals 1, call.sec
      assert.equals 500000, call.usec
    assert.equals 20, state.setsockopt_calls[1].opt
    assert.equals 21, state.setsockopt_calls[2].opt

  it "probe_ipv6 rend true si connect() réussit et false si inet_pton échoue", ->
    { mod } = load_mod {}
    assert.is_true mod.probe_ipv6 "::1", 53
    failing = (load_mod {}, { inet_pton: 0 })[1]
    assert.is_false failing.probe_ipv6 "::zz", 53

describe "doh.upstream — erreurs de création", ->

  it "rend nil + errno si socket() échoue", ->
    { mod } = load_mod {}, { socket_fail: true, errno: 97 }
    client, err = mod.new_client "127.0.0.1", 53, 2000
    assert.is_nil client
    assert.equals "socket() failed: errno=97", err

  it "rend nil si inet_pton refuse une adresse IPv4", ->
    { mod } = load_mod {}, { inet_pton: 0 }
    client, err = mod.new_client "999.1.1.1", 53, 2000
    assert.is_nil client
    assert.equals "inet_pton(AF_INET) failed for 999.1.1.1", err

  it "rend nil si inet_pton refuse une adresse IPv6", ->
    { mod } = load_mod {}, { inet_pton: 0 }
    client, err = mod.new_client "::zz", 53, 2000
    assert.is_nil client
    assert.equals "inet_pton(AF_INET6) failed for ::zz", err

  it "rend nil + errno si connect() échoue", ->
    { mod } = load_mod {}, { connect: -1, errno: 101 }
    client, err = mod.new_client "127.0.0.1", 53, 2000
    assert.is_nil client
    assert.equals "connect(AF_INET) failed: errno=101", err

describe "doh.upstream — erreurs de requête", ->

  it "rend nil + errno si send() échoue", ->
    { mod } = load_mod {}, { send_fail: true, errno: 32 }
    client = mod.new_client "127.0.0.1", 53, 2000
    resp, err = mod.query client, make_query 0x1234
    assert.is_nil resp
    assert.equals "send() failed: errno=32", err

  it "rend nil si recv() renvoie 0 (datagramme vide)", ->
    { mod } = load_mod { "" }
    client = mod.new_client "127.0.0.1", 53, 2000
    resp, err = mod.query client, make_query 0x1234
    assert.is_nil resp
    assert.equals "recv() returned 0 (connection closed)", err

  it "close tolère un handle nil ou un fd négatif", ->
    { mod, state } = load_mod {}
    assert.is_nil mod.close nil
    assert.is_nil mod.close { fd: -1 }
    assert.is_false state.closed
