local is_hex_digest
is_hex_digest = function(s)
  return type(s) == "string" and #s == 64 and s:match("^[0-9a-fA-F]+$") ~= nil
end
local bin_to_hex
bin_to_hex = function(s)
  return (s:gsub(".", function(c)
    return string.format("%02x", string.byte(c))
  end))
end
local load_sha
load_sha = function()
  local ok, mod = pcall(require, "ipparse.lib.sha")
  if ok and mod and mod.hmac and mod.sha256 and mod.hex_to_bin then
    return mod
  end
  ok, mod = pcall(require, "ipparse.lib.sha2")
  if ok and mod and mod.hmac and mod.sha256 and mod.hex_to_bin then
    return mod
  end
  ok, mod = pcall(require, "sha2")
  if ok and mod and mod.hmac and mod.sha256 and mod.hex_to_bin then
    return mod
  end
  return error("no SHA backend available for HKDF")
end
local sha = load_sha()
local hmac, sha256, hex_to_bin
hmac, sha256, hex_to_bin = sha.hmac, sha.sha256, sha.hex_to_bin
local hmac_bin
hmac_bin = function(key, msg)
  local d = hmac(sha256, key, msg)
  if is_hex_digest(d) then
    return hex_to_bin(d)
  else
    return d
  end
end
local hmac_hex
hmac_hex = function(key, msg)
  local d = hmac(sha256, key, msg)
  if is_hex_digest(d) then
    return d
  else
    return bin_to_hex(d)
  end
end
local sp, char, rep, sub
do
  local _obj_0 = require("ipparse.lib.pack_compat")
  sp, char, rep, sub = _obj_0.pack, _obj_0.char, _obj_0.rep, _obj_0.sub
end
local hkdf_extract
hkdf_extract = function(salt, ikm)
  if salt == nil then
    salt = ""
  end
  if salt == "" then
    salt = rep("\0", 64)
  end
  return hmac_bin(salt, ikm)
end
local hkdf_expand
hkdf_expand = function(prk, info, len)
  if info == nil then
    info = ""
  end
  len = len * 2
  local i, okm, t = 1, "", ""
  while #okm < len do
    t = hmac_hex(prk, hex_to_bin(t) .. info .. char(i))
    okm = okm .. t
    i = i + 1
  end
  return sub(okm, 1, len)
end
local hkdf
hkdf = function(salt, ikm, info, len)
  return hkdf_expand(hkdf_extract(salt, ikm), info, len)
end
local hkdf_expand_label
hkdf_expand_label = function(prk, label, context, len)
  return hkdf_expand(prk, sp(">Hs1s1", len, "tls13 " .. label, context), len)
end
local test
test = function()
  assert(hkdf(hex_to_bin("000102030405060708090a0b0c"), hex_to_bin("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), hex_to_bin("f0f1f2f3f4f5f6f7f8f9"), 42) == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
  assert(hkdf(hex_to_bin("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"), hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"), hex_to_bin("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"), 82) == "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87")
  assert(hkdf("", hex_to_bin("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), "", 42) == "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
  local init_secret = hkdf_extract(hex_to_bin("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"), hex_to_bin("0001020304050607"))
  local csecret = hkdf_expand_label(init_secret, "client in", "", 32)
  assert(hkdf_expand_label(hex_to_bin(csecret), "quic key", "", 16) == "b14b918124fda5c8d79847602fa3520b")
  return print("OK")
end
if arg and arg[0] == debug.getinfo(1, "S").source:sub(2) then
  print("Running tests")
  test()
end
return {
  hkdf = hkdf,
  hkdf_extract = hkdf_extract,
  hkdf_expand = hkdf_expand,
  hkdf_expand_label = hkdf_expand_label,
  hex_to_bin = hex_to_bin,
  test = test
}
