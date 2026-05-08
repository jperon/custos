local util = require("ipparse.lib.util")
local test
test = util.test
local hkdf, hkdf_extract, hkdf_expand, hkdf_expand_label, hex_to_bin
do
  local _obj_0 = require("ipparse.lib.hkdf")
  hkdf, hkdf_extract, hkdf_expand, hkdf_expand_label, hex_to_bin = _obj_0.hkdf, _obj_0.hkdf_extract, _obj_0.hkdf_expand, _obj_0.hkdf_expand_label, _obj_0.hex_to_bin
end
test("hkdf: RFC 5869 test case 1", function()
  local result = hkdf(hex_to_bin("000102030405060708090a0b0c"), hex_to_bin("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), hex_to_bin("f0f1f2f3f4f5f6f7f8f9"), 42)
  local expected = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
  return assert(result == expected, "TC1 mismatch:\ngot: " .. tostring(result) .. "\nexp: " .. tostring(expected))
end)
test("hkdf: RFC 5869 test case 3 (no salt/info)", function()
  local result = hkdf("", hex_to_bin("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), "", 42)
  local expected = "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
  return assert(result == expected, "TC3 mismatch")
end)
local dcid_hex = "8394c8f03e515708"
local quic_salt = hex_to_bin("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
test("hkdf: QUIC initial_secret (RFC 9001 §A.1)", function()
  local init_secret = hkdf_extract(quic_salt, hex_to_bin(dcid_hex))
  local csecret = hkdf_expand_label(init_secret, "client in", "", 32)
  local expected = "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"
  return assert(csecret == expected, "client_initial_secret mismatch:\ngot: " .. tostring(csecret) .. "\nexp: " .. tostring(expected))
end)
test("hkdf: QUIC client quic key (RFC 9001 §A.1)", function()
  local init_secret = hkdf_extract(quic_salt, hex_to_bin(dcid_hex))
  local csecret = hkdf_expand_label(init_secret, "client in", "", 32)
  local key = hkdf_expand_label(hex_to_bin(csecret), "quic key", "", 16)
  local expected = "1f369613dd76d5467730efcbe3b1a22d"
  return assert(key == expected, "client quic key mismatch:\ngot: " .. tostring(key) .. "\nexp: " .. tostring(expected))
end)
test("hkdf: QUIC client quic iv (RFC 9001 §A.1)", function()
  local init_secret = hkdf_extract(quic_salt, hex_to_bin(dcid_hex))
  local csecret = hkdf_expand_label(init_secret, "client in", "", 32)
  local iv = hkdf_expand_label(hex_to_bin(csecret), "quic iv", "", 12)
  local expected = "fa044b2f42a3fd3b46fb255c"
  return assert(iv == expected, "client quic iv mismatch:\ngot: " .. tostring(iv) .. "\nexp: " .. tostring(expected))
end)
test("hkdf: QUIC client hp key (RFC 9001 §A.1)", function()
  local init_secret = hkdf_extract(quic_salt, hex_to_bin(dcid_hex))
  local csecret = hkdf_expand_label(init_secret, "client in", "", 32)
  local hp = hkdf_expand_label(hex_to_bin(csecret), "quic hp", "", 16)
  local expected = "9f50449e04a0e810283a1e9933adedd2"
  return assert(hp == expected, "client hp key mismatch:\ngot: " .. tostring(hp) .. "\nexp: " .. tostring(expected))
end)
test("hkdf: QUIC server quic key (RFC 9001 §A.1)", function()
  local init_secret = hkdf_extract(quic_salt, hex_to_bin(dcid_hex))
  local ssecret = hkdf_expand_label(init_secret, "server in", "", 32)
  local key = hkdf_expand_label(hex_to_bin(ssecret), "quic key", "", 16)
  local expected = "cf3a5331653c364c88f0f379b6067e37"
  return assert(key == expected, "server quic key mismatch:\ngot: " .. tostring(key) .. "\nexp: " .. tostring(expected))
end)
return util.summary("hkdf")
