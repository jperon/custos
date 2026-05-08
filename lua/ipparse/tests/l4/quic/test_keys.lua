local util = require("ipparse.lib.util")
local test
test = util.test
local hkdf_extract, hkdf_expand_label, hex_to_bin
do
  local _obj_0 = require("ipparse.lib.hkdf")
  hkdf_extract, hkdf_expand_label, hex_to_bin = _obj_0.hkdf_extract, _obj_0.hkdf_expand_label, _obj_0.hex_to_bin
end
local derive_initial_secrets, derive_keys, INITIAL_SALT
do
  local _obj_0 = require("ipparse.l4.quic.v1.keys")
  derive_initial_secrets, derive_keys, INITIAL_SALT = _obj_0.derive_initial_secrets, _obj_0.derive_keys, _obj_0.INITIAL_SALT
end
local dcid = hex_to_bin("8394c8f03e515708")
local E_CLIENT_SECRET = "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"
local E_SERVER_SECRET = "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"
local E_CLIENT_KEY = "1f369613dd76d5467730efcbe3b1a22d"
local E_CLIENT_IV = "fa044b2f42a3fd3b46fb255c"
local E_CLIENT_HP = "9f50449e04a0e810283a1e9933adedd2"
local E_SERVER_KEY = "cf3a5331653c364c88f0f379b6067e37"
local E_SERVER_IV = "0ac1493ca1905853b0bba03e"
local E_SERVER_HP = "c206b8d9b9f0f37644430b490eeaa314"
local bin2hex
bin2hex = function(s)
  return s:gsub(".", function(c)
    return string.format("%02x", string.byte(c))
  end)
end
test("keys: INITIAL_SALT matches RFC 9001", function()
  local expected_hex = "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"
  local got_hex = bin2hex(INITIAL_SALT)
  return assert(got_hex == expected_hex, "INITIAL_SALT mismatch: " .. tostring(got_hex))
end)
test("keys: derive_initial_secrets returns client and server", function()
  local cs, ss = derive_initial_secrets(dcid)
  assert(type(cs) == "string" and #cs == 32, "client_secret must be 32 bytes")
  return assert(type(ss) == "string" and #ss == 32, "server_secret must be 32 bytes")
end)
test("keys: client_initial_secret matches RFC 9001 §A.1", function()
  local cs, _ = derive_initial_secrets(dcid)
  return assert(bin2hex(cs) == E_CLIENT_SECRET, "client_secret mismatch:\ngot: " .. tostring(bin2hex(cs)))
end)
test("keys: server_initial_secret matches RFC 9001 §A.1", function()
  local _, ss = derive_initial_secrets(dcid)
  return assert(bin2hex(ss) == E_SERVER_SECRET, "server_secret mismatch:\ngot: " .. tostring(bin2hex(ss)))
end)
test("keys: client quic key matches RFC 9001 §A.1", function()
  local cs, _ = derive_initial_secrets(dcid)
  local key
  key, _, _ = derive_keys(cs)
  return assert(bin2hex(key) == E_CLIENT_KEY, "client key mismatch:\ngot: " .. tostring(bin2hex(key)))
end)
test("keys: client quic iv matches RFC 9001 §A.1", function()
  local cs, _ = derive_initial_secrets(dcid)
  local iv
  _, iv, _ = derive_keys(cs)
  return assert(bin2hex(iv) == E_CLIENT_IV, "client iv mismatch:\ngot: " .. tostring(bin2hex(iv)))
end)
test("keys: client hp key matches RFC 9001 §A.1", function()
  local cs, _ = derive_initial_secrets(dcid)
  local hp
  _, _, hp = derive_keys(cs)
  return assert(bin2hex(hp) == E_CLIENT_HP, "client hp mismatch:\ngot: " .. tostring(bin2hex(hp)))
end)
test("keys: server quic key matches RFC 9001 §A.1", function()
  local _, ss = derive_initial_secrets(dcid)
  local key
  key, _, _ = derive_keys(ss)
  return assert(bin2hex(key) == E_SERVER_KEY, "server key mismatch:\ngot: " .. tostring(bin2hex(key)))
end)
test("keys: server quic iv matches RFC 9001 §A.1", function()
  local _, ss = derive_initial_secrets(dcid)
  local iv
  _, iv, _ = derive_keys(ss)
  return assert(bin2hex(iv) == E_SERVER_IV, "server iv mismatch:\ngot: " .. tostring(bin2hex(iv)))
end)
test("keys: server hp key matches RFC 9001 §A.1", function()
  local _, ss = derive_initial_secrets(dcid)
  local hp
  _, _, hp = derive_keys(ss)
  return assert(bin2hex(hp) == E_SERVER_HP, "server hp mismatch:\ngot: " .. tostring(bin2hex(hp)))
end)
return util.summary("keys")
