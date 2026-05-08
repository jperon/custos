local band, bor, bxor, rshift
do
  local _obj_0 = require("ipparse.lib.bit_compat")
  band, bor, bxor, rshift = _obj_0.band, _obj_0.bor, _obj_0.bxor, _obj_0.rshift
end
local sp, su
do
  local _obj_0 = require("ipparse.lib.pack_compat")
  sp, su = _obj_0.pack, _obj_0.unpack
end
local byte = string.byte
local tunpack = table.unpack or unpack
local construct_nonce
construct_nonce = function(iv, pn)
  local buf = {
    byte(iv, 1, 12)
  }
  for i = 12, 5, -1 do
    buf[i] = bxor(buf[i], band(pn, 0xFF))
    pn = rshift(pn, 8)
  end
  return string.char(tunpack(buf))
end
local sample_from_packet
sample_from_packet = function(pkt, enc_off)
  local s = enc_off + 4
  assert(s + 15 <= #pkt, "packet too short to extract header protection sample")
  return pkt:sub(s, s + 15)
end
local apply_header_mask
apply_header_mask = function(hdr_bytes, first_byte_idx, pn_off, pn_len, mask, long)
  local m0 = byte(mask, 1)
  local fb_mask = long and 0x0F or 0x1F
  hdr_bytes[first_byte_idx] = bxor(hdr_bytes[first_byte_idx], band(m0, fb_mask))
  for i = 1, pn_len do
    hdr_bytes[pn_off + i - 1] = bxor(hdr_bytes[pn_off + i - 1], byte(mask, i + 1))
  end
end
local recover_packet_number = nil
local unprotect_header
unprotect_header = function(pkt, pn_off, hp_key, long, expected_pn, crypto)
  local sample = sample_from_packet(pkt, pn_off)
  local mask = crypto.aes_128_ecb_block(hp_key, sample)
  local m0 = byte(mask, 1)
  local fb_mask = long and 0x0F or 0x1F
  local first = bxor(byte(pkt, 1), band(m0, fb_mask))
  local pn_len = band(first, 0x03) + 1
  local truncated_pn = 0
  local pn_chars = { }
  for i = 1, pn_len do
    local b = bxor(byte(pkt, pn_off + i - 1), byte(mask, i + 1))
    truncated_pn = truncated_pn * 256 + b
    pn_chars[i] = string.char(b)
  end
  local full_pn = recover_packet_number(truncated_pn, expected_pn, pn_len)
  local aad = string.char(first) .. (pn_off > 2 and pkt:sub(2, pn_off - 1) or "") .. table.concat(pn_chars)
  return aad, full_pn, pn_len
end
local pn_from_bytes
pn_from_bytes = function(hdr_bytes, pn_off, pn_len)
  local pn = 0
  for i = 0, pn_len - 1 do
    pn = pn * 256 + hdr_bytes[pn_off + i]
  end
  return pn
end
recover_packet_number = function(truncated, expected, pn_len)
  local pn_win = 1
  for _ = 1, pn_len * 8 do
    pn_win = pn_win * 2
  end
  local pn_hwin = rshift(pn_win, 1)
  local candidate = (expected - (expected % pn_win)) + truncated
  if candidate <= expected - pn_hwin then
    return candidate + pn_win
  elseif candidate > expected + pn_hwin and candidate >= pn_win then
    return candidate - pn_win
  else
    return candidate
  end
end
local remove_header_protection
remove_header_protection = function(pkt, pn_off, hp_key, long, expected_pn, crypto)
  local aad, full_pn, pn_len = unprotect_header(pkt, pn_off, hp_key, long, expected_pn, crypto)
  local hdr_bytes = { }
  for i = 1, #aad do
    hdr_bytes[i] = byte(aad, i)
  end
  return hdr_bytes, full_pn, pn_len
end
local decrypt_payload
decrypt_payload = function(pkt, payload_off, key, iv, pn, aad, crypto)
  local nonce = construct_nonce(iv, pn)
  local ciphertext_with_tag = pkt:sub(payload_off)
  return crypto.aes_128_gcm_decrypt(key, nonce, ciphertext_with_tag, aad)
end
local encrypt_payload
encrypt_payload = function(plaintext, key, iv, pn, aad, crypto)
  local nonce = construct_nonce(iv, pn)
  return crypto.aes_128_gcm_encrypt(key, nonce, plaintext, aad)
end
return {
  construct_nonce = construct_nonce,
  sample_from_packet = sample_from_packet,
  unprotect_header = unprotect_header,
  remove_header_protection = remove_header_protection,
  recover_packet_number = recover_packet_number,
  decrypt_payload = decrypt_payload,
  encrypt_payload = encrypt_payload
}
