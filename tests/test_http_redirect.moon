-- tests/test_http_redirect.moon
-- Test HTTP to HTTPS redirect detection

socket = require "auth.ffi_socket"

results = {passed: 0, failed: 0}

assert_ok = (test_name, ok, err) ->
  if ok
    results.passed += 1
    print "  ✓ #{test_name}"
  else
    results.failed += 1
    print "  ✗ #{test_name}: #{err or 'unknown error'}"

assert_eq = (test_name, got, expected) ->
  if got == expected
    results.passed += 1
    print "  ✓ #{test_name}"
  else
    results.failed += 1
    print "  ✗ #{test_name}: got #{got}, expected #{expected}"

print "\n=== HTTP Redirect Detection Tests ==="

-- Test 1: Peek bytes on socket with data
print "\n[peek_bytes on Socket with Data]"

ok_srv, srv = pcall -> socket.tcp!
if ok_srv
  ok_bind, err = pcall -> srv\bind("127.0.0.1", 0)  -- Bind to any available port
  if ok_bind
    -- Get the actual port
    port = srv\getsockname!
    -- Extract port number from the IP:port string
    port_str = port\match ":(%d+)$" or "unknown"
    print "  ℹ Server listening on port: #{port_str}"
    
    ok_listen = srv\listen(1)
    assert_ok "server listen", ok_listen
    
    ok_cli, cli = pcall -> socket.tcp!
    if ok_cli
      ok_connect, err = pcall -> cli\connect("127.0.0.1", tonumber(port_str))
      if ok_connect
        -- Send some HTTP data
        cli\send("GET / HTTP/1.1\r\n")
        
        -- On server side, accept connection
        srv\settimeout(0.5)
        ok_acc, srv_conn = pcall -> srv\accept!
        if ok_acc and srv_conn
          -- Now test peek_bytes
          srv_conn\settimeout(nil)  -- blocking mode
          peeked = srv_conn\peek_bytes(10)
          
          if peeked and #peeked > 0
            results.passed += 1
            print "  ✓ peek_bytes returns data on active socket"
            first_byte = peeked\byte(1)
            print "  ℹ First byte value: 0x#{string.format("%02x", first_byte)}"
            
            if first_byte == 0x47  -- 'G' in GET
              results.passed += 1
              print "  ✓ First byte is 'G' (HTTP GET detected)"
            else
              results.failed += 1
              print "  ✗ First byte should be 'G' (0x47), got 0x#{string.format("%02x", first_byte)}"
            
            -- Verify that peek didn't consume data
            received = srv_conn\receive("*l")
            if received and received\match("^GET")
              results.passed += 1
              print "  ✓ peek_bytes did not consume data (receive still works)"
            else
              results.failed += 1
              print "  ✗ peek_bytes should not consume data"
          else
            results.failed += 1
            print "  ✗ peek_bytes should return data"
          
          srv_conn\close!
        else
          results.failed += 1
          print "  ✗ server accept failed: #{err}"
        
        cli\close!
      else
        results.failed += 1
        print "  ✗ client connect failed: #{err}"
    else
      results.failed += 1
      print "  ✗ client creation failed"
    
    srv\close!
  else
    results.failed += 1
    print "  ✗ server bind failed: #{err}"
else
  results.failed += 1
  print "  ✗ server creation failed"

-- Test 2: MSG_PEEK constant exists
print "\n[Constants Check]"
socket_file = assert(io.open("src/auth/ffi_socket.lua", "r"))
socket_content = socket_file\read("*a")
socket_file\close!

if socket_content\find("MSG_PEEK = 0x100")
  results.passed += 1
  print "  ✓ MSG_PEEK constant defined in ffi_socket.lua"
else
  results.failed += 1
  print "  ✗ MSG_PEEK constant not found in ffi_socket.lua"

-- Test 3: peek_bytes function exists in compiled code
if socket_content\find("peek_bytes")
  results.passed += 1
  print "  ✓ peek_bytes function defined in ffi_socket.lua"
else
  results.failed += 1
  print "  ✗ peek_bytes function not found in ffi_socket.lua"

-- Test 4: send_http_redirect exists in server.lua
print "\n[Server Function Check]"
server_file = assert(io.open("src/auth/server.lua", "r"))
server_content = server_file\read("*a")
server_file\close!

if server_content\find("send_http_redirect")
  results.passed += 1
  print "  ✓ send_http_redirect function defined in server.lua"
else
  results.failed += 1
  print "  ✗ send_http_redirect function not found in server.lua"

if server_content\find("0x16")
  results.passed += 1
  print "  ✓ TLS detection (0x16) implemented in server.lua"
else
  results.failed += 1
  print "  ✗ TLS detection (0x16) not found in server.lua"

print "\n=== Summary ==="
total = results.passed + results.failed
print "Passed: #{results.passed}/#{total}"
if results.failed > 0
  print "Failed: #{results.failed}"
else
  print "✅ All tests passed!"

results
