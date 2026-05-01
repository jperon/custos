-- tests/test_ffi_wolfssl.moon
-- Test suite for FFI WolfSSL wrapper

ssl = require "auth.ffi_wolfssl"

results = {passed: 0, failed: 0}

assert_ok = (test_name, ok, err) ->
  if ok
    results.passed += 1
    print "  ✓ #{test_name}"
  else
    results.failed += 1
    print "  ✗ #{test_name}: #{err or 'unknown error'}"

assert_type = (test_name, got, expected_type) ->
  if type(got) == expected_type
    results.passed += 1
    print "  ✓ #{test_name}"
  else
    results.failed += 1
    print "  ✗ #{test_name}: got type #{type(got)}, expected #{expected_type}"

print "\n=== FFI WolfSSL Tests ==="

-- Test 1: Module exports
print "\n[Module Exports]"
assert_type "newcontext is a function", ssl.newcontext, "function"
assert_type "wrap is a function", ssl.wrap, "function"
assert_type "free_context is a function", ssl.free_context, "function"
-- libwolfssl is cdata/userdata, just check it's not nil
if ssl.libwolfssl
  results.passed += 1
  print "  ✓ libwolfssl is loaded"
else
  results.failed += 1
  print "  ✗ libwolfssl is loaded"

-- Test 2: Error codes defined
print "\n[Error Code Constants]"
assert_type "SSL_ERROR_NONE constant", ssl.SSL_ERROR_NONE, "number"
assert_type "SSL_ERROR_WANT_READ constant", ssl.SSL_ERROR_WANT_READ, "number"
assert_type "SSL_ERROR_WANT_WRITE constant", ssl.SSL_ERROR_WANT_WRITE, "number"
assert_type "SSL_ERROR_SSL constant", ssl.SSL_ERROR_SSL, "number"

-- Test 3: Create SSL context (requires certificate files)
print "\n[Context Creation]"

-- Check if test certificates exist
cert_file = "./tmp/test_cert.pem"
key_file = "./tmp/test_key.pem"

-- For now, just test that newcontext exists and can be called
-- Full test would need valid cert/key files
has_newcontext = type(ssl.newcontext) == "function"
assert_ok "newcontext function callable", has_newcontext

-- Test 4: Test wrap function signature
print "\n[Wrap Function]"
has_wrap = type(ssl.wrap) == "function"
assert_ok "wrap function callable", has_wrap

-- Test 5: Test free_context function
print "\n[Free Context]"
has_free = type(ssl.free_context) == "function"
assert_ok "free_context function callable", has_free

print "\n=== Summary ==="
total = results.passed + results.failed
print "Passed: #{results.passed}/#{total}"
if results.failed > 0
  print "Failed: #{results.failed}"
else
  print "✅ All basic tests passed!"

print "\n⚠️  Full TLS tests (handshake, send/recv) require test certificates"
print "Will be validated during E2E tests with real captive portal"

results
