local socket = require("auth.ffi_socket")
local results = {
  passed = 0,
  failed = 0
}
local assert_ok
assert_ok = function(test_name, ok, err)
  if ok then
    results.passed = results.passed + 1
    return print("  ✓ " .. tostring(test_name))
  else
    results.failed = results.failed + 1
    return print("  ✗ " .. tostring(test_name) .. ": " .. tostring(err or 'unknown error'))
  end
end
local assert_eq
assert_eq = function(test_name, got, expected)
  if got == expected then
    results.passed = results.passed + 1
    return print("  ✓ " .. tostring(test_name))
  else
    results.failed = results.failed + 1
    return print("  ✗ " .. tostring(test_name) .. ": got " .. tostring(got) .. ", expected " .. tostring(expected))
  end
end
print("\n=== HTTP Redirect Detection Tests ===")
print("\n[peek_bytes on Socket with Data]")
local ok_srv, srv = pcall(function()
  return socket.tcp()
end)
if ok_srv then
  local ok_bind, err = pcall(function()
    return srv:bind("127.0.0.1", 0)
  end)
  if ok_bind then
    local port = srv:getsockname()
    local port_str = port:match(":(%d+)$" or "unknown")
    print("  ℹ Server listening on port: " .. tostring(port_str))
    local ok_listen = srv:listen(1)
    assert_ok("server listen", ok_listen)
    local ok_cli, cli = pcall(function()
      return socket.tcp()
    end)
    if ok_cli then
      local ok_connect
      ok_connect, err = pcall(function()
        return cli:connect("127.0.0.1", tonumber(port_str))
      end)
      if ok_connect then
        cli:send("GET / HTTP/1.1\r\n")
        srv:settimeout(0.5)
        local ok_acc, srv_conn = pcall(function()
          return srv:accept()
        end)
        if ok_acc and srv_conn then
          srv_conn:settimeout(nil)
          local peeked = srv_conn:peek_bytes(10)
          if peeked and #peeked > 0 then
            results.passed = results.passed + 1
            print("  ✓ peek_bytes returns data on active socket")
            local first_byte = peeked:byte(1)
            print("  ℹ First byte value: 0x" .. tostring(string.format("%02x", first_byte)))
            if first_byte == 0x47 then
              results.passed = results.passed + 1
              print("  ✓ First byte is 'G' (HTTP GET detected)")
            else
              results.failed = results.failed + 1
              print("  ✗ First byte should be 'G' (0x47), got 0x" .. tostring(string.format("%02x", first_byte)))
            end
            local received = srv_conn:receive("*l")
            if received and received:match("^GET") then
              results.passed = results.passed + 1
              print("  ✓ peek_bytes did not consume data (receive still works)")
            else
              results.failed = results.failed + 1
              print("  ✗ peek_bytes should not consume data")
            end
          else
            results.failed = results.failed + 1
            print("  ✗ peek_bytes should return data")
          end
          srv_conn:close()
        else
          results.failed = results.failed + 1
          print("  ✗ server accept failed: " .. tostring(err))
        end
        cli:close()
      else
        results.failed = results.failed + 1
        print("  ✗ client connect failed: " .. tostring(err))
      end
    else
      results.failed = results.failed + 1
      print("  ✗ client creation failed")
    end
    srv:close()
  else
    results.failed = results.failed + 1
    print("  ✗ server bind failed: " .. tostring(err))
  end
else
  results.failed = results.failed + 1
  print("  ✗ server creation failed")
end
print("\n[Constants Check]")
local socket_file = assert(io.open("src/auth/ffi_socket.lua", "r"))
local socket_content = socket_file:read("*a")
socket_file:close()
if socket_content:find("MSG_PEEK = 0x100") then
  results.passed = results.passed + 1
  print("  ✓ MSG_PEEK constant defined in ffi_socket.lua")
else
  results.failed = results.failed + 1
  print("  ✗ MSG_PEEK constant not found in ffi_socket.lua")
end
if socket_content:find("peek_bytes") then
  results.passed = results.passed + 1
  print("  ✓ peek_bytes function defined in ffi_socket.lua")
else
  results.failed = results.failed + 1
  print("  ✗ peek_bytes function not found in ffi_socket.lua")
end
print("\n[Server Function Check]")
local server_file = assert(io.open("src/auth/server.lua", "r"))
local server_content = server_file:read("*a")
server_file:close()
if server_content:find("send_http_redirect") then
  results.passed = results.passed + 1
  print("  ✓ send_http_redirect function defined in server.lua")
else
  results.failed = results.failed + 1
  print("  ✗ send_http_redirect function not found in server.lua")
end
if server_content:find("0x16") then
  results.passed = results.passed + 1
  print("  ✓ TLS detection (0x16) implemented in server.lua")
else
  results.failed = results.failed + 1
  print("  ✗ TLS detection (0x16) not found in server.lua")
end
print("\n=== Summary ===")
local total = results.passed + results.failed
print("Passed: " .. tostring(results.passed) .. "/" .. tostring(total))
if results.failed > 0 then
  print("Failed: " .. tostring(results.failed))
else
  print("✅ All tests passed!")
end
return results
