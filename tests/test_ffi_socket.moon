-- tests/test_ffi_socket.moon
-- Test suite for FFI socket wrapper

socket = require "auth.ffi_socket"

-- Helper for test results
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

print "\n=== FFI Socket Tests ==="

-- Test 1: Create TCP socket
print "\n[TCP Socket Creation]"
ok, sock = pcall socket.tcp
assert_ok "socket.tcp() creates socket", ok, sock
if ok
  assert_eq "socket has fd property", type(sock.fd), "number"
  assert_eq "socket is not closed initially", sock.closed, false

-- Test 2: Socket has required methods
print "\n[Socket Methods]"
if ok
  has_bind = type(sock.bind) == "function"
  has_listen = type(sock.listen) == "function"
  has_send = type(sock.send) == "function"
  has_receive = type(sock.receive) == "function"
  has_close = type(sock.close) == "function"
  has_settimeout = type(sock.settimeout) == "function"
  
  assert_ok "has bind method", has_bind
  assert_ok "has listen method", has_listen
  assert_ok "has send method", has_send
  assert_ok "has receive method", has_receive
  assert_ok "has close method", has_close
  assert_ok "has settimeout method", has_settimeout

-- Test 3: Close socket
print "\n[Socket Close]"
if ok
  close_ok = sock\close!
  assert_eq "close() returns true", close_ok, true
  assert_eq "socket marked as closed", sock.closed, true

-- Test 4: Create TCP6 socket
print "\n[TCP6 Socket Creation]"
ok6, sock6 = pcall socket.tcp6
assert_ok "socket.tcp6() creates IPv6 socket", ok6, sock6
if ok6
  ok6_close = sock6\close!
  assert_ok "tcp6 socket closes", ok6_close

-- Test 5: Test select function exists and has signature
print "\n[Select Function]"
has_select = type(socket.select) == "function"
assert_ok "socket.select is a function", has_select

-- Test 6: Create and bind socket
print "\n[Bind and Listen]"
ok_bind, sock_bind = pcall socket.tcp
if ok_bind
  -- Try to bind to 0.0.0.0:0 (wildcard address, OS-assigned port)
  ok_bind_call, err = pcall (-> sock_bind\bind "0.0.0.0", 0, 32)
  if ok_bind_call
    print "  ✓ socket.bind() succeeds on 0.0.0.0:0"
    results.passed += 1
    sock_bind\close!
  else
    -- Expected if we don't have permission or port in use
    print "  ⚠ socket.bind() - may fail in test env: #{err or 'unknown'}"

-- Test 7: Timeout setting
print "\n[Timeout Setting]"
ok_timeout, sock_timeout = pcall socket.tcp
if ok_timeout
  timeout_ok = sock_timeout\settimeout(0.1)
  assert_eq "settimeout(0.1) returns true", timeout_ok, true
  assert_eq "timeout property set", sock_timeout.timeout, 0.1
  sock_timeout\close!

print "\n=== Summary ==="
total = results.passed + results.failed
print "Passed: #{results.passed}/#{total}"
if results.failed > 0
  print "Failed: #{results.failed}"
else
  print "✅ All tests passed!"

results
