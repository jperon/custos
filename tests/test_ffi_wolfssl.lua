local ssl = require("auth.ffi_wolfssl")
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
local assert_type
assert_type = function(test_name, got, expected_type)
  if type(got) == expected_type then
    results.passed = results.passed + 1
    return print("  ✓ " .. tostring(test_name))
  else
    results.failed = results.failed + 1
    return print("  ✗ " .. tostring(test_name) .. ": got type " .. tostring(type(got)) .. ", expected " .. tostring(expected_type))
  end
end
print("\n=== FFI WolfSSL Tests ===")
print("\n[Module Exports]")
assert_type("newcontext is a function", ssl.newcontext, "function")
assert_type("wrap is a function", ssl.wrap, "function")
assert_type("free_context is a function", ssl.free_context, "function")
if ssl.libwolfssl then
  results.passed = results.passed + 1
  print("  ✓ libwolfssl is loaded")
else
  results.failed = results.failed + 1
  print("  ✗ libwolfssl is loaded")
end
print("\n[Error Code Constants]")
assert_type("SSL_ERROR_NONE constant", ssl.SSL_ERROR_NONE, "number")
assert_type("SSL_ERROR_WANT_READ constant", ssl.SSL_ERROR_WANT_READ, "number")
assert_type("SSL_ERROR_WANT_WRITE constant", ssl.SSL_ERROR_WANT_WRITE, "number")
assert_type("SSL_ERROR_SSL constant", ssl.SSL_ERROR_SSL, "number")
print("\n[Context Creation]")
local cert_file = "./tmp/test_cert.pem"
local key_file = "./tmp/test_key.pem"
local has_newcontext = type(ssl.newcontext) == "function"
assert_ok("newcontext function callable", has_newcontext)
print("\n[Wrap Function]")
local has_wrap = type(ssl.wrap) == "function"
assert_ok("wrap function callable", has_wrap)
print("\n[Free Context]")
local has_free = type(ssl.free_context) == "function"
assert_ok("free_context function callable", has_free)
print("\n=== Summary ===")
local total = results.passed + results.failed
print("Passed: " .. tostring(results.passed) .. "/" .. tostring(total))
if results.failed > 0 then
  print("Failed: " .. tostring(results.failed))
else
  print("✅ All basic tests passed!")
end
print("\n⚠️  Full TLS tests (handshake, send/recv) require test certificates")
print("Will be validated during E2E tests with real captive portal")
return results
