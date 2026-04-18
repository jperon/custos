#!/usr/bin/env moon

--- Debug AEAD Test
-- Very basic test to debug the AEAD issue

print "=== Debug AEAD Test ==="

-- Test string operations first
pack: sp, unpack: su = string
{:band, :bor, :bnot, :lshift, :rshift} = require "ipparse.lib.bit_compat"

test_data = "test"
print "Test data: #{test_data}"
print "Length: #{#test_data}"

for i = 1, #test_data
  byte_val = su "B", test_data, i
  print "Byte #{i}: #{byte_val} (#{string.char(byte_val)})"

print "String unpack test passed"

-- Test basic XOR
val_a = 65  -- 'A'
val_b = 66  -- 'B'
val_c = band(bor(val_a, val_b), bnot(band(val_a, val_b)))
print "XOR test: #{val_a} ~ #{val_b} = #{val_c}"

-- Now test our module
aead = require "ipparse.lib.crypto.aead"
print "AEAD module loaded successfully"

-- Test the nonce construction only
iv = string.rep("\0", 12)  -- 12 zero bytes
packet_number = 1

print "Testing nonce construction..."
nonce = aead.construct_nonce iv, packet_number
print "Nonce constructed successfully, length: #{#nonce}"

print "Debug test complete!"
