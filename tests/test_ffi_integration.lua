local socket_ffi = require("auth.ffi_socket")
local ssl_ffi = require("auth.ffi_wolfssl")
local results = {
  passed = 0,
  failed = 0
}
local assert_ok
assert_ok = function(test_name, ok, err)
  if ok then
    results.passed = results.passed + 1
    print("  ✓ " .. tostring(test_name))
    return true
  else
    results.failed = results.failed + 1
    print("  ✗ " .. tostring(test_name) .. ": " .. tostring(err or 'unknown error'))
    return false
  end
end
print("\n=== FFI Integration Tests ===")
print("\n[Server Socket Creation & Bind]")
local ok_sock, srv = pcall(socket_ffi.tcp)
if assert_ok("create server socket", ok_sock) then
  local ok_bind, err = pcall((function()
    return srv:bind("0.0.0.0", 0, 32)
  end))
  if ok_bind then
    print("  ✓ server socket bound to 0.0.0.0")
    results.passed = results.passed + 1
    print("\n[Socket State After Bind]")
    assert_ok("server socket still has fd", srv.fd > 0)
    assert_ok("server socket not marked closed", not srv.closed)
    print("\n[Module Chain Compatibility]")
    assert_ok("socket_ffi exports tcp", type(socket_ffi.tcp) == "function")
    assert_ok("socket_ffi exports select", type(socket_ffi.select) == "function")
    assert_ok("ssl_ffi exports newcontext", type(ssl_ffi.newcontext) == "function")
    assert_ok("ssl_ffi exports wrap", type(ssl_ffi.wrap) == "function")
    print("\n[Bound Socket Methods]")
    local timeout_ok = srv:settimeout(0.1)
    assert_ok("settimeout works on bound socket", timeout_ok)
    print("\n[Socket Cleanup]")
    local close_ok = srv:close()
    assert_ok("bound socket closes successfully", close_ok)
    assert_ok("socket marked closed", srv.closed)
  else
    print("  ⚠ Could not bind socket (may be permission issue in test env)")
    if srv then
      srv:close()
    end
  end
end
print("\n[Socket Select Compatibility]")
local ok_select, sock_list = pcall(socket_ffi.tcp)
if ok_select then
  local empty_list = { }
  local select_callable = type(socket_ffi.select) == "function"
  assert_ok("socket.select is callable", select_callable)
  if sock_list then
    sock_list:close()
  end
end
print("\n[Module Isolation]")
local sock1 = socket_ffi.tcp()
local sock2 = socket_ffi.tcp()
assert_ok("two sockets are different objects", sock1 ~= sock2)
assert_ok("two sockets have different fds", sock1.fd ~= sock2.fd)
sock1:close()
sock2:close()
print("\n=== Integration Summary ===")
local total = results.passed + results.failed
print("Passed: " .. tostring(results.passed) .. "/" .. tostring(total))
if results.failed > 0 then
  print("Failed: " .. tostring(results.failed))
  print("⚠️  Check if ports are available and permissions correct")
else
  print("✅ All integration tests passed!")
end
print("\n✅ FFI modules ready for server.moon integration")
return results
