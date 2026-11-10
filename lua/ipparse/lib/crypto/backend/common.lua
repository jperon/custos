local bxor
bxor = require("ipparse.lib.bit_compat").bxor
local byte, char
do
  local _obj_0 = string
  byte, char = _obj_0.byte, _obj_0.char
end
local unpack = unpack or table.unpack
local validate_gcm_key
validate_gcm_key = function(key)
  assert(#key == 16, "AES-128-GCM key must be 16 bytes (got " .. tostring(#key) .. ")")
  return true
end
local validate_gcm_nonce
validate_gcm_nonce = function(nonce)
  assert(#nonce == 12, "AES-128-GCM nonce must be 12 bytes (got " .. tostring(#nonce) .. ")")
  return true
end
local validate_ecb_key
validate_ecb_key = function(key)
  assert(#key == 16, "AES-128-ECB key must be 16 bytes (got " .. tostring(#key) .. ")")
  return true
end
local validate_ecb_block
validate_ecb_block = function(block)
  assert(#block == 16, "AES-128-ECB block must be 16 bytes (got " .. tostring(#block) .. ")")
  return true
end
local validate_quic_iv
validate_quic_iv = function(iv)
  assert(#iv == 12, "IV must be 12 bytes (got " .. tostring(#iv) .. ")")
  return true
end
local construct_nonce
construct_nonce = function(iv, packet_number)
  validate_quic_iv(iv)
  local buf = {
    byte(iv, 1, 12)
  }
  local pn = packet_number
  for i = 12, 5, -1 do
    local b = pn % 256
    buf[i] = bxor(buf[i], b)
    pn = (pn - b) / 256
  end
  return char(unpack(buf))
end
local split_ct_tag
split_ct_tag = function(ciphertext_with_tag)
  if #ciphertext_with_tag < 16 then
    return nil, "ciphertext too short (no room for auth tag)"
  end
  return ciphertext_with_tag:sub(1, #ciphertext_with_tag - 16), ciphertext_with_tag:sub(#ciphertext_with_tag - 15)
end
return {
  validate_gcm_key = validate_gcm_key,
  validate_gcm_nonce = validate_gcm_nonce,
  validate_ecb_key = validate_ecb_key,
  validate_ecb_block = validate_ecb_block,
  validate_quic_iv = validate_quic_iv,
  construct_nonce = construct_nonce,
  split_ct_tag = split_ct_tag
}
