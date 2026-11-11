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
make_socket_stub = (recv_script) ->
  state = { sent: {}, recv_calls: 0, closed: false }
  mod = {
    C: {
      socket: -> 42
      close: (fd) -> state.closed = true
      setsockopt: (fd, level, opt, val, len) -> 0
      inet_pton: (af, src, dst) -> 1
      connect: (fd, addr, len) -> 0
      send: (fd, data, len, flags) ->
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

load_mod = (recv_script) ->
  socket_stub = make_socket_stub recv_script
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
