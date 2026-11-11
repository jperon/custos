-- tests/unit/lib/http_spec.moon
-- Tests des helpers HTTP purs (lib/http).

{ :read_request, :send_response, :apply_io_timeouts } = require "lib.http"

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

describe "lib/http.apply_io_timeouts", ->
  it "pose rcvtimeo et sndtimeo sur le socket client", ->
    opts = {}
    client = {
      setoption: (_self, name, value) -> opts[name] = value
    }
    apply_io_timeouts client, 15
    assert.equals 15, opts.rcvtimeo
    assert.equals 15, opts.sndtimeo

  it "retombe sur 15 s si la valeur est nil ou invalide", ->
    opts = {}
    client = { setoption: (_self, name, value) -> opts[name] = value }
    apply_io_timeouts client, nil
    assert.equals 15, opts.rcvtimeo
    apply_io_timeouts client, "abc"
    assert.equals 15, opts.rcvtimeo

describe "lib/http.read_request — bornes", ->
  make_counting_client = (script) ->
    i = 0
    {
      receive: (_self, _mode) ->
        i += 1
        step = script[math.min i, #script]
        step[1], step[2]
      calls: -> i
    }

  it "refuse un Content-Length au-dessus de max_body sans lire le corps", ->
    client = make_counting_client {
      { "POST /dns-query HTTP/1.1" }
      { "Content-Length: 100000" }
      { "" }
    }
    req, err = read_request client, max_body: 65536
    assert.is_nil req
    assert.equals "body_too_large", err
    assert.equals 2, client.calls!

  it "accepte un corps exactement à la borne", ->
    client = make_counting_client {
      { "POST / HTTP/1.1" }
      { "Content-Length: 10" }
      { "" }
      { "0123456789" }
    }
    req, err = read_request client, max_body: 10
    assert.is_nil err
    assert.equals "0123456789", req.body

  it "refuse une longueur négative, non numérique ou non entière", ->
    for value in *{"-5", "abc", "1e10"}
      client = make_counting_client {
        { "POST / HTTP/1.1" }
        { "Content-Length: #{value}" }
        { "" }
      }
      req, err = read_request client, max_body: 100
      assert.is_nil req, "valeur acceptée à tort : #{value}"
      assert.equals "body_too_large", err
      assert.equals 2, client.calls!

  it "refuse trop de lignes d'en-tête", ->
    client = make_counting_client {
      { "GET / HTTP/1.1" }
      { "A: 1" }
      { "B: 2" }
      { "C: 3" }
      { "D: 4" }
      { "" }
    }
    req, err = read_request client, max_headers: 3
    assert.is_nil req
    assert.equals "headers_too_large", err

  it "refuse une ligne d'en-tête trop longue", ->
    client = make_counting_client {
      { "GET / HTTP/1.1" }
      { "X: 01234567890123456789" }
      { "" }
    }
    req, err = read_request client, max_header_line: 10
    assert.is_nil req
    assert.equals "headers_too_large", err
