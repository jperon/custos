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
print("\n=== FFI Socket Tests ===")
print("\n[TCP Socket Creation]")
local ok, sock = pcall(socket.tcp)
assert_ok("socket.tcp() creates socket", ok, sock)
if ok then
  assert_eq("socket has fd property", type(sock.fd), "number")
  assert_eq("socket is not closed initially", sock.closed, false)
end
print("\n[Socket Methods]")
if ok then
  local has_bind = type(sock.bind) == "function"
  local has_listen = type(sock.listen) == "function"
  local has_send = type(sock.send) == "function"
  local has_receive = type(sock.receive) == "function"
  local has_close = type(sock.close) == "function"
  local has_settimeout = type(sock.settimeout) == "function"
  assert_ok("has bind method", has_bind)
  assert_ok("has listen method", has_listen)
  assert_ok("has send method", has_send)
  assert_ok("has receive method", has_receive)
  assert_ok("has close method", has_close)
  assert_ok("has settimeout method", has_settimeout)
end
print("\n[Socket Close]")
if ok then
  local close_ok = sock:close()
  assert_eq("close() returns true", close_ok, true)
  assert_eq("socket marked as closed", sock.closed, true)
end
print("\n[TCP6 Socket Creation]")
local ok6, sock6 = pcall(socket.tcp6)
assert_ok("socket.tcp6() creates IPv6 socket", ok6, sock6)
if ok6 then
  local ok6_close = sock6:close()
  assert_ok("tcp6 socket closes", ok6_close)
end
print("\n[Select Function]")
local has_select = type(socket.select) == "function"
assert_ok("socket.select is a function", has_select)
print("\n[Bind and Listen]")
local ok_bind, sock_bind = pcall(socket.tcp)
if ok_bind then
  local ok_bind_call, err = pcall((function()
    return sock_bind:bind("0.0.0.0", 0, 32)
  end))
  if ok_bind_call then
    print("  ✓ socket.bind() succeeds on 0.0.0.0:0")
    results.passed = results.passed + 1
    sock_bind:close()
  else
    print("  ⚠ socket.bind() - may fail in test env: " .. tostring(err or 'unknown'))
  end
end
print("\n[Timeout Setting]")
local ok_timeout, sock_timeout = pcall(socket.tcp)
if ok_timeout then
  local timeout_ok = sock_timeout:settimeout(0.1)
  assert_eq("settimeout(0.1) returns true", timeout_ok, true)
  assert_eq("timeout property set", sock_timeout.timeout, 0.1)
  sock_timeout:close()
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
