local read_request, send_response
do
  local _obj_0 = require("lib.http")
  read_request, send_response = _obj_0.read_request, _obj_0.send_response
end
describe("lib/http.read_request", function()
  local make_client
  make_client = function(script)
    local i = 0
    return {
      receive = function(_self, _mode)
        i = i + 1
        local step = script[math.min(i, #script)]
        return step[1], step[2]
      end
    }
  end
  it("lit une requête complète", function()
    local client = make_client({
      {
        "GET /ping HTTP/1.1"
      },
      {
        "Host: example"
      },
      {
        ""
      }
    })
    local req = read_request(client)
    assert.equals("GET", req.method)
    assert.equals("/ping", req.path)
    return assert.equals("example", req.headers.host)
  end)
  it("réessaie sur want_read_write transitoire", function()
    local client = make_client({
      {
        nil,
        "want_read_write"
      },
      {
        "GET / HTTP/1.1"
      },
      {
        ""
      }
    })
    local req = read_request(client)
    return assert.equals("GET", req.method)
  end)
  it("opts.timeout borne les retries want_read_write (connexion muette)", function()
    local original_os_time = os.time
    local t = original_os_time()
    os.time = function()
      return t
    end
    local client = {
      receive = function(_self, _mode)
        t = t + 10
        return nil, "want_read_write"
      end
    }
    local req, err = read_request(client, {
      timeout = 15
    })
    os.time = original_os_time
    assert.is_nil(req)
    return assert.equals("timeout", err)
  end)
  return it("sans opts, échec après épuisement des retries", function()
    local client = {
      receive = function(_self, _mode)
        return nil, "eof_from_peer"
      end
    }
    local req, err = read_request(client)
    assert.is_nil(req)
    return assert.equals("eof_from_peer", err)
  end)
end)
return describe("lib/http.send_response", function()
  it("retourne peer_closed si le client coupe pendant l'écriture", function()
    local client = {
      send = function(_self, _chunk)
        return error("wolfSSL_write() failed (ret: 0, error code: 5, ssl_err: 308ULL:error state on socket | 397ULL:Peer closed underlying transport Error)")
      end
    }
    local ok, err = send_response(client, 200, { }, "hello")
    assert.is_nil(ok)
    return assert.equals("peer_closed", err)
  end)
  it("retourne send_timeout si send rend nil (WANT_WRITE après SO_SNDTIMEO)", function()
    local client = {
      send = function(_self, _chunk)
        return nil
      end
    }
    local ok, err = send_response(client, 200, { }, "hello")
    assert.is_nil(ok)
    return assert.equals("send_timeout", err)
  end)
  return it("écrit une réponse HTTP complète si tout va bien", function()
    local writes = { }
    local client = {
      send = function(_self, chunk)
        writes[#writes + 1] = chunk
        return true
      end
    }
    local ok, err = send_response(client, 200, {
      ["Content-Type"] = "text/plain"
    }, "abc")
    assert.is_true(ok)
    assert.is_nil(err)
    local joined = table.concat(writes)
    assert.truthy(joined:find("HTTP/1.1 200 OK\r\n", 1, true))
    assert.truthy(joined:find("Content-Length: 3\r\n", 1, true))
    return assert.truthy(joined:find("\r\n\r\nabc", 1, true))
  end)
end)
