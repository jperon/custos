local sp, su
do
  local _obj_0 = require("ipparse.lib.pack_compat")
  sp, su = _obj_0.pack, _obj_0.unpack
end
local hkdf = require("ipparse.lib.hkdf")
local aead = require("ipparse.lib.crypto.aead")
local bin2hex, hex2bin
do
  local _obj_0 = require("ipparse.init")
  bin2hex, hex2bin = _obj_0.bin2hex, _obj_0.hex2bin
end
local band, bor, bnot, lshift, rshift
do
  local _obj_0 = require("ipparse.lib.bit_compat")
  band, bor, bnot, lshift, rshift = _obj_0.band, _obj_0.bor, _obj_0.bnot, _obj_0.lshift, _obj_0.rshift
end
local xor
xor = function(a, b)
  return band(bor(a, b), bnot(band(a, b)))
end
local QUIC_V1_INITIAL_SALT = hex2bin("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
local QUIC_LABELS = {
  CLIENT_INITIAL = "client in",
  SERVER_INITIAL = "server in",
  HEADER_PROTECTION = "quic hp",
  PACKET_PROTECTION_KEY = "quic key",
  PACKET_PROTECTION_IV = "quic iv"
}
local derive_initial_secrets
derive_initial_secrets = function(connection_id)
  local initial_secret = hkdf.hkdf_extract(QUIC_V1_INITIAL_SALT, connection_id)
  local client_secret = hex2bin(hkdf.hkdf_expand_label(initial_secret, QUIC_LABELS.CLIENT_INITIAL, "", 32))
  local server_secret = hex2bin(hkdf.hkdf_expand_label(initial_secret, QUIC_LABELS.SERVER_INITIAL, "", 32))
  return client_secret, server_secret
end
local derive_packet_protection_keys
derive_packet_protection_keys = function(initial_secret)
  local packet_key = hex2bin(hkdf.hkdf_expand_label(initial_secret, QUIC_LABELS.PACKET_PROTECTION_KEY, "", 16))
  local packet_iv = hex2bin(hkdf.hkdf_expand_label(initial_secret, QUIC_LABELS.PACKET_PROTECTION_IV, "", 12))
  local hp_key = hex2bin(hkdf.hkdf_expand_label(initial_secret, QUIC_LABELS.HEADER_PROTECTION, "", 16))
  return packet_key, packet_iv, hp_key
end
local stub_aes_ecb_encrypt
stub_aes_ecb_encrypt = function(key, plaintext)
  if not (#key == 16) then
    error("AES key must be 16 bytes")
  end
  if not (#plaintext == 16) then
    error("AES-ECB input must be 16 bytes")
  end
  local ciphertext = ""
  for i = 1, 16 do
    local p = string.byte(plaintext, i)
    local k = string.byte(key, ((i - 1) % #key) + 1)
    ciphertext = ciphertext .. string.char(xor(p, k))
  end
  return ciphertext
end
local generate_header_mask
generate_header_mask = function(hp_key, sample)
  if not (#hp_key == 16) then
    error("Header protection key must be 16 bytes")
  end
  if not (#sample == 16) then
    error("Sample must be 16 bytes")
  end
  local mask_block = stub_aes_ecb_encrypt(hp_key, sample)
  return mask_block:sub(1, 5)
end
local remove_header_protection
remove_header_protection = function(protected_header, hp_key, sample, is_long_header)
  if is_long_header == nil then
    is_long_header = true
  end
  if not (#protected_header >= (is_long_header and 4 or 1)) then
    error("Header too short for protection removal")
  end
  local mask = generate_header_mask(hp_key, sample)
  local unprotected = ""
  for i = 1, #protected_header do
    unprotected = unprotected .. string.char(string.byte(protected_header, i))
  end
  if is_long_header then
    local first_byte = string.byte(protected_header, 1)
    local mask_first = string.byte(mask, 1)
    local unprotected_first = xor(first_byte, band(mask_first, 0x0F))
    unprotected = string.char(unprotected_first) .. unprotected:sub(2)
    local pn_length = band(unprotected_first, 0x03) + 1
    local pn_offset = is_long_header and (#protected_header - pn_length + 1) or 2
    for i = 1, pn_length do
      if pn_offset + i - 1 <= #protected_header then
        local protected_byte = string.byte(protected_header, pn_offset + i - 1)
        local mask_byte = string.byte(mask, i + 1)
        local unprotected_byte = xor(protected_byte, mask_byte)
        local before = unprotected:sub(1, pn_offset + i - 2)
        local after = unprotected:sub(pn_offset + i)
        unprotected = before .. string.char(unprotected_byte) .. after
      end
    end
    local packet_number = 0
    for i = 1, pn_length do
      if pn_offset + i - 1 <= #unprotected then
        local byte_val = string.byte(unprotected, pn_offset + i - 1)
        packet_number = bor(lshift(packet_number, 8), byte_val)
      end
    end
    return unprotected, packet_number
  else
    local first_byte = string.byte(protected_header, 1)
    local mask_first = string.byte(mask, 1)
    local unprotected_first = xor(first_byte, band(mask_first, 0x1F))
    unprotected = string.char(unprotected_first) .. unprotected:sub(2)
    local pn_length = band(unprotected_first, 0x03) + 1
    local packet_number = 0
    for i = 1, pn_length do
      if 1 + i <= #protected_header then
        local protected_byte = string.byte(protected_header, 1 + i)
        local mask_byte = string.byte(mask, i + 1)
        local unprotected_byte = xor(protected_byte, mask_byte)
        local before = unprotected:sub(1, i)
        local after = unprotected:sub(i + 2)
        unprotected = before .. string.char(unprotected_byte) .. after
        packet_number = bor(lshift(packet_number, 8), unprotected_byte)
      end
    end
    return unprotected, packet_number
  end
end
local recover_packet_number
recover_packet_number = function(truncated_pn, expected_pn, pn_nbits)
  local pn_win = lshift(1, pn_nbits)
  local pn_hwin = pn_win // 2
  local pn_mask = pn_win - 1
  local candidate_pn = bor(band(expected_pn, bnot(pn_mask)), truncated_pn)
  if candidate_pn <= expected_pn - pn_hwin then
    return candidate_pn + pn_win
  elseif candidate_pn > expected_pn + pn_hwin then
    return candidate_pn - pn_win
  else
    return candidate_pn
  end
end
local recover_quic_packet_number
recover_quic_packet_number = function(protected_header, hp_key, sample, expected_pn, is_long_header)
  if is_long_header == nil then
    is_long_header = true
  end
  local unprotected_header, truncated_pn = remove_header_protection(protected_header, hp_key, sample, is_long_header)
  local pn_nbits = 8
  local full_pn = recover_packet_number(truncated_pn, expected_pn, pn_nbits)
  return unprotected_header, full_pn
end
return {
  derive_initial_secrets = derive_initial_secrets,
  derive_packet_protection_keys = derive_packet_protection_keys,
  generate_header_mask = generate_header_mask,
  remove_header_protection = remove_header_protection,
  recover_packet_number = recover_packet_number,
  recover_quic_packet_number = recover_quic_packet_number,
  QUIC_V1_INITIAL_SALT = QUIC_V1_INITIAL_SALT,
  QUIC_LABELS = QUIC_LABELS
}
