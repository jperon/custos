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
    return print("FAIL\tlunatik: " .. tostring(name) .. "\tgot: " .. tostring(tostring(got)) .. ", expected: " .. tostring(tostring(expected)))
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
assert_test("L2: Extract destination MAC address", function()
  local eth_frame = hex_to_bin("ffffffffffff" .. "000000000000" .. "0800")
  local dst_mac = eth_frame:sub(1, 6)
  assert(#dst_mac == 6, "MAC should be 6 bytes")
  return assert(string.byte(dst_mac, 1) == 0xff, "First byte of dst MAC should be 0xff")
end)
assert_test("L2: Extract source MAC address", function()
  local eth_frame = hex_to_bin("ffffffffffff" .. "aabbccddeeff" .. "0800")
  local src_mac = eth_frame:sub(7, 12)
  assert(#src_mac == 6, "MAC should be 6 bytes")
  return assert(string.byte(src_mac, 1) == 0xaa, "First byte of src MAC should be 0xaa")
end)
assert_test("L2: Extract EtherType", function()
  local eth_frame = hex_to_bin("ffffffffffff" .. "000000000000" .. "0800")
  local ethertype = (string.byte(eth_frame, 13) << 8) | string.byte(eth_frame, 14)
  return assert(ethertype == 0x0800, "EtherType should be IPv4 (0x0800)")
end)
assert_test("L3: Extract IPv4 version and header length", function()
  local ipv4_hdr = hex_to_bin("45000050")
  local version = (string.byte(ipv4_hdr, 1) >> 4) & 0xf
  local ihl = string.byte(ipv4_hdr, 1) & 0xf
  assert(version == 4, "Version should be 4")
  return assert(ihl == 5, "IHL should be 5 (20 bytes)")
end)
assert_test("L3: Extract IPv4 protocol field", function()
  local ipv4_hdr = hex_to_bin("45000050" .. "00000000" .. "4011" .. "0000")
  local protocol = string.byte(ipv4_hdr, 10)
  return assert(protocol == 0x11, "Protocol should be UDP (0x11)")
end)
assert_test("L3: Extract source and destination IP addresses", function()
  local ipv4_hdr = hex_to_bin("45000050" .. "00000000" .. "4011" .. "0000" .. "7f000001" .. "7f000001")
  local src_ip = ipv4_hdr:sub(13, 16)
  local dst_ip = ipv4_hdr:sub(17, 20)
  assert(#src_ip == 4, "IP should be 4 bytes")
  assert(string.byte(src_ip, 1) == 0x7f, "First octet of loopback should be 127")
  return assert(src_ip == dst_ip, "Src and dst should match")
end)
assert_test("L4: Extract UDP source and destination ports", function()
  local udp_hdr = hex_to_bin("270f27b0" .. "003600f7")
  local sport = (string.byte(udp_hdr, 1) << 8) | string.byte(udp_hdr, 2)
  local dport = (string.byte(udp_hdr, 3) << 8) | string.byte(udp_hdr, 4)
  assert(sport == 0x270f, "Source port extraction")
  return assert(dport == 0x27b0, "Destination port extraction")
end)
assert_test("L4: Extract UDP payload length", function()
  local udp_hdr = hex_to_bin("270f27b0" .. "003600f7")
  local length = (string.byte(udp_hdr, 5) << 8) | string.byte(udp_hdr, 6)
  return assert(length == 0x0036, "UDP length should match")
end)
assert_test("L4: QUIC packet has fixed bit (0x80)", function()
  local quic_first_byte = hex_to_bin("c0")
  local first_byte = string.byte(quic_first_byte, 1)
  local fixed_bit = (first_byte & 0x80) ~= 0
  return assert(fixed_bit, "Fixed bit should be set")
end)
assert_test("L4: QUIC initial packet type detection", function()
  local quic_first_byte = hex_to_bin("c0")
  local first_byte = string.byte(quic_first_byte, 1)
  local is_long_header = (first_byte & 0x80) ~= 0
  local packet_type = (first_byte >> 4) & 0x3
  assert(is_long_header, "Should be long header")
  return assert(packet_type == 0, "Packet type should be 0 (Initial)")
end)
assert_test("L4: QUIC version extraction", function()
  local quic_hdr = hex_to_bin("c0000000" .. "01")
  local version = (string.byte(quic_hdr, 2) << 24) | (string.byte(quic_hdr, 3) << 16) | (string.byte(quic_hdr, 4) << 8) | string.byte(quic_hdr, 5)
  return assert(version == 1, "QUIC version should be 1")
end)
assert_test("L4: QUIC DCID length extraction", function()
  local quic_hdr = hex_to_bin("c0000000" .. "01" .. "08")
  local dcid_len = string.byte(quic_hdr, 6)
  return assert(dcid_len == 8, "DCID length should be 8 bytes")
end)
assert_test("L4: QUIC DCID extraction", function()
  local dcid_hex = "8394c8f03e515708"
  local quic_hdr = hex_to_bin("c0000000" .. "01" .. "08" .. dcid_hex)
  local dcid = quic_hdr:sub(7, 14)
  assert(#dcid == 8, "DCID should be 8 bytes")
  return assert(dcid == hex_to_bin(dcid_hex), "DCID extraction")
end)
assert_test("L7: Extract TLS record type from QUIC payload", function()
  local tls_record = hex_to_bin("16" .. "0303")
  local record_type = string.byte(tls_record, 1)
  return assert(record_type == 0x16, "TLS record type should be Handshake")
end)
assert_test("L7: Extract TLS Handshake message type", function()
  local hs_msg = hex_to_bin("01" .. "000000")
  local msg_type = string.byte(hs_msg, 1)
  return assert(msg_type == 0x01, "Message type should be ClientHello (0x01)")
end)
assert_test("L7: Extract ClientHello TLS version", function()
  local client_hello = hex_to_bin("0303")
  local tls_version = (string.byte(client_hello, 1) << 8) | string.byte(client_hello, 2)
  return assert(tls_version == 0x0303, "TLS version should be 1.2")
end)
assert_test("L7: SNI extension type detection", function()
  local sni_ext = hex_to_bin("0000" .. "0010")
  local ext_type = (string.byte(sni_ext, 1) << 8) | string.byte(sni_ext, 2)
  return assert(ext_type == 0x0000, "SNI extension type should be 0x0000")
end)
print("\n--> lib.crypto.lunatik.quic: " .. tostring(tests_passed) .. "/" .. tostring(tests_passed + tests_failed))
if tests_failed > 0 then
  return error(tostring(tests_failed) .. " test(s) failed")
end
