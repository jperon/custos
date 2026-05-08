local send_response
send_response = require("lib.http").send_response
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
