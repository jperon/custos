-- tests/unit/lib/http_spec.moon
-- Tests des helpers HTTP purs (lib/http).

{ :send_response } = require "lib.http"

describe "lib/http.send_response", ->
  it "retourne peer_closed si le client coupe pendant l'écriture", ->
    client = {
      send: (_self, _chunk) ->
        error "wolfSSL_write() failed (ret: 0, error code: 5, ssl_err: 308ULL:error state on socket | 397ULL:Peer closed underlying transport Error)"
    }

    ok, err = send_response client, 200, {}, "hello"
    assert.is_nil ok
    assert.equals "peer_closed", err

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
