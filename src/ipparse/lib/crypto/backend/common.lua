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
return {
  validate_gcm_key = validate_gcm_key,
  validate_gcm_nonce = validate_gcm_nonce,
  validate_ecb_key = validate_ecb_key,
  validate_ecb_block = validate_ecb_block,
  validate_quic_iv = validate_quic_iv
}
