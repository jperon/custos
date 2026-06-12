-- tests/unit/lib/http_spec.moon
-- Tests des helpers HTTP purs (lib/http).

{ :read_request, :send_response } = require "lib.http"

describe "lib/http.read_request", ->
  -- Client factice : rejoue une liste de réponses [data, err] à chaque receive.
  make_client = (script) ->
    i = 0
    {
      receive: (_self, _mode) ->
        i += 1
        step = script[math.min i, #script]
        step[1], step[2]
    }

  it "lit une requête complète", ->
    client = make_client {
      { "GET /ping HTTP/1.1" }
      { "Host: example" }
      { "" }
    }
    req = read_request client
    assert.equals "GET", req.method
    assert.equals "/ping", req.path
    assert.equals "example", req.headers.host

  it "réessaie sur want_read_write transitoire", ->
    client = make_client {
      { nil, "want_read_write" }
      { "GET / HTTP/1.1" }
      { "" }
    }
    req = read_request client
    assert.equals "GET", req.method

  it "opts.timeout borne les retries want_read_write (connexion muette)", ->
    -- Sans deadline, 50 retries × SO_RCVTIMEO tiendraient le processus
    -- AUTH-conn des minutes sur une connexion qui n'envoie jamais rien.
    original_os_time = os.time
    t = original_os_time!
    os.time = -> t
    client = {
      receive: (_self, _mode) ->
        t += 10  -- chaque receive bloque 10 s (simule SO_RCVTIMEO)
        nil, "want_read_write"
    }
    req, err = read_request client, timeout: 15
    os.time = original_os_time
    assert.is_nil req
    assert.equals "timeout", err

  it "sans opts, échec après épuisement des retries", ->
    client = { receive: (_self, _mode) -> nil, "eof_from_peer" }
    req, err = read_request client
    assert.is_nil req
    assert.equals "eof_from_peer", err

describe "lib/http.send_response", ->
  it "retourne peer_closed si le client coupe pendant l'écriture", ->
    client = {
      send: (_self, _chunk) ->
        error "wolfSSL_write() failed (ret: 0, error code: 5, ssl_err: 308ULL:error state on socket | 397ULL:Peer closed underlying transport Error)"
    }

    ok, err = send_response client, 200, {}, "hello"
    assert.is_nil ok
    assert.equals "peer_closed", err

  it "retourne send_timeout si send rend nil (WANT_WRITE après SO_SNDTIMEO)", ->
    client = { send: (_self, _chunk) -> nil }
    ok, err = send_response client, 200, {}, "hello"
    assert.is_nil ok
    assert.equals "send_timeout", err

  it "écrit une réponse HTTP complète si tout va bien", ->
    writes = {}
    client = {
      send: (_self, chunk) ->
        writes[#writes + 1] = chunk
        true
    }

    ok, err = send_response client, 200, { ["Content-Type"]: "text/plain" }, "abc"
    assert.is_true ok
    assert.is_nil err
    joined = table.concat writes
    assert.truthy joined\find("HTTP/1.1 200 OK\r\n", 1, true)
    assert.truthy joined\find("Content-Length: 3\r\n", 1, true)
    assert.truthy joined\find("\r\n\r\nabc", 1, true)
