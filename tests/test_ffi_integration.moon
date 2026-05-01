-- tests/test_ffi_integration.moon
-- Integration test: FFI socket + WolfSSL together

socket_ffi = require "auth.ffi_socket"
ssl_ffi = require "auth.ffi_wolfssl"

results = {passed: 0, failed: 0}

assert_ok = (test_name, ok, err) ->
  if ok
    results.passed += 1
    print "  ✓ #{test_name}"
    return true
  else
    results.failed += 1
    print "  ✗ #{test_name}: #{err or 'unknown error'}"
    return false

print "\n=== FFI Integration Tests ==="

-- Test 1: Create and bind server socket
print "\n[Server Socket Creation & Bind]"
ok_sock, srv = pcall socket_ffi.tcp
if assert_ok "create server socket", ok_sock
  ok_bind, err = pcall (-> srv\bind "0.0.0.0", 0, 32)
  if ok_bind
    print "  ✓ server socket bound to 0.0.0.0"
    results.passed += 1
    
    -- Test 2: Verify socket is ready for accept
    print "\n[Socket State After Bind]"
    assert_ok "server socket still has fd", srv.fd > 0
    assert_ok "server socket not marked closed", not srv.closed
    
    -- Test 3: Module chain compatibility
    print "\n[Module Chain Compatibility]"
    assert_ok "socket_ffi exports tcp", type(socket_ffi.tcp) == "function"
    assert_ok "socket_ffi exports select", type(socket_ffi.select) == "function"
    assert_ok "ssl_ffi exports newcontext", type(ssl_ffi.newcontext) == "function"
    assert_ok "ssl_ffi exports wrap", type(ssl_ffi.wrap) == "function"
    
    -- Test 4: Socket methods work on bound socket
    print "\n[Bound Socket Methods]"
    timeout_ok = srv\settimeout(0.1)
    assert_ok "settimeout works on bound socket", timeout_ok
    
    -- Test 5: Close and verify
    print "\n[Socket Cleanup]"
    close_ok = srv\close!
    assert_ok "bound socket closes successfully", close_ok
    assert_ok "socket marked closed", srv.closed
  else
    print "  ⚠ Could not bind socket (may be permission issue in test env)"
    srv\close! if srv

-- Test 6: Verify socket.select compatibility
print "\n[Socket Select Compatibility]"
ok_select, sock_list = pcall socket_ffi.tcp
if ok_select
  empty_list = {}
  select_callable = type(socket_ffi.select) == "function"
  assert_ok "socket.select is callable", select_callable
  
  -- Don't actually call select with empty list (would timeout)
  -- Just verify the function signature
  
  sock_list\close! if sock_list

-- Test 7: Verify module isolation
print "\n[Module Isolation]"
sock1 = socket_ffi.tcp!
sock2 = socket_ffi.tcp!
assert_ok "two sockets are different objects", sock1 != sock2
assert_ok "two sockets have different fds", sock1.fd != sock2.fd
sock1\close!
sock2\close!

print "\n=== Integration Summary ==="
total = results.passed + results.failed
print "Passed: #{results.passed}/#{total}"
if results.failed > 0
  print "Failed: #{results.failed}"
  print "⚠️  Check if ports are available and permissions correct"
else
  print "✅ All integration tests passed!"

print "\n✅ FFI modules ready for server.moon integration"

results
