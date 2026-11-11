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
local hex_to_bin
hex_to_bin = function(hex)
  return (hex:gsub("..", function(cc)
    return string.char(tonumber(cc, 16))
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
  return nil
end
local load_crypto_hkdf
load_crypto_hkdf = function()
  local ok, mod = pcall(require, "crypto.hkdf")
  if ok and mod and mod.new then
    return mod
  end
  return nil
end
local load_crypto_shash
load_crypto_shash = function()
  local ok, crypto = pcall(require, "crypto")
  if not (ok and crypto and crypto.shash) then
    return nil
  end
  return crypto.shash
end
local crypto_hkdf = load_crypto_hkdf()
local crypto_shash = nil
if not (crypto_hkdf) then
  crypto_shash = load_crypto_shash()
end
local sha = nil
local hmac, sha256 = nil, nil
if not (crypto_hkdf or crypto_shash) then
  sha = load_sha()
  if not (sha) then
    error("no SHA backend available for HKDF")
  end
  hmac, sha256 = sha.hmac, sha.sha256
  if sha.hex_to_bin then
    hex_to_bin = sha.hex_to_bin
  end
end
local hkdf_tfm = nil
local shash_tfm = nil
local get_hkdf
get_hkdf = function()
  if not (hkdf_tfm) then
    hkdf_tfm = crypto_hkdf.new("sha256")
  end
  return hkdf_tfm
end
local get_shash
get_shash = function()
  if not (shash_tfm) then
    shash_tfm = crypto_shash("hmac(sha256)")
  end
  return shash_tfm
end
local hmac_shash_bin
hmac_shash_bin = function(key, msg)
  local h = get_shash()
  h:setkey(key)
  return h:digest(msg)
end
local hmac_bin
hmac_bin = function(key, msg)
  if crypto_shash then
    return hmac_shash_bin(key, msg)
  end
  if not (hmac and sha256) then
    error("hmac backend unavailable")
  end
  local d = hmac(sha256, key, msg)
  if is_hex_digest(d) then
    return hex_to_bin(d)
  else
    return d
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
  if crypto_hkdf then
    return get_hkdf():extract(salt, ikm)
  end
  return hmac_bin(salt, ikm)
end
local hkdf_expand_bin
hkdf_expand_bin = function(prk, info, len)
  if info == nil then
    info = ""
  end
  if crypto_hkdf then
    return get_hkdf():expand(prk, info, len)
  end
  local i, total, t, parts = 1, 0, "", { }
  while total < len do
    t = hmac_bin(prk, t .. info .. char(i))
    parts[i] = t
    total = total + #t
    i = i + 1
  end
  return sub(table.concat(parts), 1, len)
end
local hkdf_expand
hkdf_expand = function(prk, info, len)
  if info == nil then
    info = ""
  end
  return bin_to_hex((hkdf_expand_bin(prk, info, len)))
end
local hkdf
hkdf = function(salt, ikm, info, len)
  if crypto_hkdf then
    return bin_to_hex(get_hkdf():hkdf(salt, ikm, info, len))
  end
  return hkdf_expand(hkdf_extract(salt, ikm), info, len)
end
local hkdf_expand_label_bin
hkdf_expand_label_bin = function(prk, label, context, len)
  return hkdf_expand_bin(prk, sp(">Hs1s1", len, "tls13 " .. label, context), len)
end
local hkdf_expand_label
hkdf_expand_label = function(prk, label, context, len)
  return bin_to_hex((hkdf_expand_label_bin(prk, label, context, len)))
end
return {
  hkdf = hkdf,
  hkdf_extract = hkdf_extract,
  hkdf_expand = hkdf_expand,
  hkdf_expand_label = hkdf_expand_label,
  hkdf_expand_bin = hkdf_expand_bin,
  hkdf_expand_label_bin = hkdf_expand_label_bin,
  hex_to_bin = hex_to_bin
}
