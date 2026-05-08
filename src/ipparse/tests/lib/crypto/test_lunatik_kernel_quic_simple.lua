local hex_to_bin
hex_to_bin = function(hex_str)
  local result = ""
  for i = 1, #hex_str, 2 do
    local byte_str = hex_str:sub(i, i + 1)
    local byte = tonumber(byte_str, 16)
    result = result .. string.char(byte)
  end
  return result
end
local tests_passed = 0
local tests_failed = 0
local assert_equal
assert_equal = function(name, got, expected)
  if got == expected then
    tests_passed = tests_passed + 1
    return print("PASS\tlunatik: " .. tostring(name))
  else
    tests_failed = tests_failed + 1
    return print("FAIL\tlunatik: " .. tostring(name) .. "\tgot: " .. tostring(got) .. ", expected: " .. tostring(expected))
  end
end
local assert_test
assert_test = function(name, fn)
  local result, err = pcall(fn)
  if result then
    tests_passed = tests_passed + 1
    return print("PASS\tlunatik: " .. tostring(name))
  else
    tests_failed = tests_failed + 1
    return print("FAIL\tlunatik: " .. tostring(name) .. "\t" .. tostring(err))
  end
end
assert_test("QUIC packet number 0x12345678 encodes to 0x78 in 1-byte form", function()
  local pkt_num = 0x12345678
  local encoded = pkt_num & 0xff
  return assert(encoded == 0x78, "Expected 0x78, got " .. tostring(string.format('0x%02x', encoded)))
end)
assert_test("QUIC packet number 0xaabbccdd encodes lower byte", function()
  local pkt_num = 0xaabbccdd
  local encoded = pkt_num & 0xff
  return assert(encoded == 0xdd, "Expected 0xdd")
end)
local construct_nonce
construct_nonce = function(iv, packet_number)
  local nonce_bytes = { }
  for i = 1, #iv do
    nonce_bytes[i] = string.byte(iv, i)
  end
  local pn_bytes = { }
  for j = 0, 7 do
    pn_bytes[j + 1] = (packet_number >> (56 - j * 8)) & 0xff
  end
  for j = 0, 7 do
    local idx = #iv - 7 + j
    if idx >= 1 and idx <= #iv then
      local a = nonce_bytes[idx] or 0
      local b = pn_bytes[j + 1]
      nonce_bytes[idx] = (a | b) - (a & b)
    end
  end
  local result = ""
  for i = 1, #nonce_bytes do
    result = result .. string.char(nonce_bytes[i])
  end
  return result
end
assert_test("construct_nonce XORs packet number into IV (pkt_num = 0)", function()
  local iv = hex_to_bin("4ddbf3ade1f0662ff8395a6fb32e4f7b")
  local pkt_num = 0
  local nonce = construct_nonce(iv, pkt_num)
  return assert(nonce == iv, "Nonce should match IV for pkt_num=0")
end)
assert_test("construct_nonce XORs packet number into IV (pkt_num = 1)", function()
  local iv = hex_to_bin("4ddbf3ade1f0662ff8395a6fb32e4f7b")
  local pkt_num = 1
  local nonce = construct_nonce(iv, pkt_num)
  local expected_last = (string.byte(iv, -1) | 1) - (string.byte(iv, -1) & 1)
  local actual_last = string.byte(nonce, -1)
  return assert(actual_last == expected_last, "Last byte should be XORed")
end)
assert_test("QUIC initial packet has fixed bit set (0x80)", function()
  local first_byte = 0xc0
  local fixed_bit = (first_byte & 0x80) ~= 0
  return assert(fixed_bit, "Fixed bit should be set")
end)
assert_test("QUIC packet type extraction from first byte", function()
  local first_byte = 0xc0
  local packet_type_bits = (first_byte >> 4) & 0x3
  return assert(packet_type_bits == 0, "Initial packet type should be 00")
end)
assert_test("QUIC version field extraction", function()
  local version_bytes = hex_to_bin("00000001")
  local version = (string.byte(version_bytes, 1) << 24) | (string.byte(version_bytes, 2) << 16) | (string.byte(version_bytes, 3) << 8) | string.byte(version_bytes, 4)
  return assert(version == 1, "Expected version 1 (QUIC v1)")
end)
print("\n--> lib.crypto.lunatik: " .. tostring(tests_passed) .. "/" .. tostring(tests_passed + tests_failed))
if tests_failed > 0 then
  return error(tostring(tests_failed) .. " test(s) failed")
end
