local su, sub, byte
do
  local _obj_0 = string
  su, sub, byte = _obj_0.unpack, _obj_0.sub, _obj_0.byte
end
local ClientHello
ClientHello = require("l7.tls.handshake.client_hello").parse
local ServerName
ServerName = require("l7.tls.handshake.extension.server_name").parse
local derive_initial_secrets, derive_keys, remove_header_protection, decrypt_payload
do
  local _obj_0 = require("l4.quic.crypto")
  derive_initial_secrets, derive_keys, remove_header_protection, decrypt_payload = _obj_0.derive_initial_secrets, _obj_0.derive_keys, _obj_0.remove_header_protection, _obj_0.decrypt_payload
end
local QUIC_VERSION_1 = 0x00000001
local parse_varint
parse_varint = function(self, data, off)
  assert(type(data) == "string", "Invalid data: must be string")
  assert(type(off) == "number" and off >= 1, "Invalid offset")
  if #data < off then
    return nil, nil, "Data too short for varint parsing"
  end
  local first_byte = byte(data, off)
  if not (first_byte) then
    return nil, nil, "Failed to read byte from data"
  end
  local len_indicator = (first_byte & 0xC0) >> 6
  local _ = val, next_read_off
  local _exp_0 = len_indicator
  if 0 == _exp_0 then
    local val = first_byte & 0x3F
    local next_read_off = off + 1
  elseif 1 == _exp_0 then
    if #data < off + 2 then
      return nil, nil, "Data too short for 2-byte varint"
    end
    local raw_val = su(">H", data, off)
    local val = raw_val & 0x3FFF
    local next_read_off = off + 2
  elseif 2 == _exp_0 then
    if #data < off + 4 then
      return nil, nil, "Data too short for 4-byte varint"
    end
    local raw_val = su(">I4", data, off)
    local val = raw_val & 0x3FFFFFFF
    local next_read_off = off + 4
  elseif 3 == _exp_0 then
    if #data < off + 8 then
      return nil, nil, "Data too short for 8-byte varint"
    end
    local raw_val = su(">I8", data, off)
    local val = raw_val & 0x3FFFFFFFFFFFFFFF
    local next_read_off = off + 8
  else
    return nil, nil, "Invalid varint length indicator"
  end
  return val, next_read_off
end.parse_varint
local parse_initial_header
parse_initial_header = function(self, data, off)
  if off == nil then
    off = 1
  end
  assert(type(data) == "string", "Invalid data: must be string")
  assert(type(off) == "number" and off >= 1, "Invalid offset")
  if #data < off then
    return nil, nil, "Data too short for header parsing"
  end
  local first_byte = byte(data, off)
  if not (first_byte) then
    return nil, nil, "Failed to read first byte"
  end
  local header_form = (first_byte & 0x80) >> 7
  local packet_type = (first_byte & 0x30) >> 4
  if header_form ~= 1 or packet_type ~= 0 then
    return nil, nil, "Not an Initial packet"
  end
  off = off + 1
  if #data < off + 4 then
    return nil, nil, "Data too short for version field"
  end
  local version, next_off = su(">I4", data, off)
  if not (version) then
    return nil, nil, "Failed to parse version"
  end
  if version ~= QUIC_VERSION_1 then
    return nil, nil, "Unsupported QUIC version"
  end
  off = next_off
  if #data < off + 1 then
    return nil, nil, "Data too short for DCID length"
  end
  local dcid_len = byte(data, off)
  if not (dcid_len) then
    return nil, nil, "Failed to read DCID length"
  end
  off = off + 1
  if #data < off + dcid_len then
    return nil, nil, "Data too short for DCID"
  end
  local dcid = sub(data, off, off + dcid_len - 1)
  off = off + dcid_len
  if #data < off + 1 then
    return nil, nil, "Data too short for SCID length"
  end
  local scid_len = byte(data, off)
  if not (scid_len) then
    return nil, nil, "Failed to read SCID length"
  end
  off = off + 1
  if #data < off + scid_len then
    return nil, nil, "Data too short for SCID"
  end
  local scid = sub(data, off, off + scid_len - 1)
  off = off + scid_len
  local token_len, err
  token_len, next_off, err = parse_varint(data, off)
  if not (token_len) then
    return nil, nil, err or "Failed to parse token length"
  end
  off = next_off
  if #data < off + token_len then
    return nil, nil, "Data too short for token"
  end
  local token = sub(data, off, off + token_len - 1)
  off = off + token_len
  local payload_len
  payload_len, next_off, err = parse_varint(data, off)
  if not (payload_len) then
    return nil, nil, err or "Failed to parse payload length"
  end
  off = next_off
  local pn_length = (first_byte & 0x03) + 1
  return {
    version = version,
    dcid = dcid,
    scid = scid,
    token = token,
    payload_len = payload_len,
    pn_length = pn_length,
    packet_type = packet_type,
    header_form = header_form,
    byte1 = first_byte,
    long_header = true,
    data_off = off,
    payload_off = off + payload_len,
    pn_offset = off
  }, off
end.parse_initial_header
local parse_crypto_frame
parse_crypto_frame = function(self, payload, off)
  if off == nil then
    off = 1
  end
  assert(type(payload) == "string", "Invalid payload: must be string")
  assert(type(off) == "number" and off >= 1, "Invalid offset")
  if #payload < off then
    return nil, nil, "Payload too short for frame parsing"
  end
  local frame_type = byte(payload, off)
  if not (frame_type) then
    return nil, nil, "Failed to read frame type"
  end
  if frame_type ~= 0x06 then
    return nil, nil, "Not a CRYPTO frame"
  end
  off = off + 1
  local _, next_off, err = parse_varint(payload, off)
  if not (next_off) then
    return nil, nil, err or "Failed to parse frame offset"
  end
  off = next_off
  local crypto_len
  crypto_len, next_off, err = parse_varint(payload, off)
  if not (crypto_len) then
    return nil, nil, err or "Failed to parse frame length"
  end
  off = next_off
  if #payload < off + crypto_len - 1 then
    return nil, nil, "Payload too short for frame data"
  end
  local crypto_data = sub(payload, off, off + crypto_len - 1)
  return crypto_data, off + crypto_len
end.parse_crypto_frame
local extract_sni_from_crypto
extract_sni_from_crypto = function(self, crypto_data)
  assert(type(crypto_data) == "string", "Invalid crypto_data: must be string")
  local ch = ClientHello(crypto_data)
  if not (ch and ch.version and ch.extensions) then
    return nil, "Failed to parse ClientHello"
  end
  local _list_0 = ch.extensions
  for _index_0 = 1, #_list_0 do
    local ext = _list_0[_index_0]
    if #ext < 4 then
      return nil, "Invalid extension data"
    end
    local ext_type = su(">H", ext, 1)
    if not (ext_type) then
      return nil, "Failed to parse extension type"
    end
    if ext_type == 0x0000 then
      local ext_data = sub(ext, 5)
      if not (ext_data) then
        return nil, "Failed to extract extension data"
      end
      local sn = ServerName(ext_data)
      if sn and sn.name then
        return sn.name
      end
    end
    local _ = end
  end
  return nil, "No SNI found in ClientHello"
end.extract_sni_from_crypto
local extract_sni
extract_sni = function(self, packet_data)
  assert(type(packet_data) == "string", "Invalid packet_data: must be string")
  local header, pn_offset, err = parse_initial_header(packet_data)
  if not (header) then
    return nil, err or "Failed to parse QUIC header"
  end
  local client_secret
  client_secret, err = derive_initial_secrets(header.dcid)
  if not (client_secret) then
    return nil, err or "Failed to derive initial secrets"
  end
  local client_key, client_iv, client_hp
  client_key, client_iv, client_hp, err = derive_keys(client_secret)
  if not (client_key) then
    return nil, err or "Failed to derive keys"
  end
  local unprotected_packet, packet_number
  unprotected_packet, packet_number, err = remove_header_protection(packet_data, pn_offset, header.pn_length, client_hp)
  if not (unprotected_packet) then
    return nil, err or "Failed to remove header protection"
  end
  local payload_offset = pn_offset + header.pn_length
  local decrypted_payload = decrypt_payload(unprotected_packet, payload_offset, packet_number, client_key, client_iv)
  if not (decrypted_payload) then
    return nil, "Failed to decrypt payload"
  end
  local crypto_data, _
  crypto_data, _, err = parse_crypto_frame(decrypted_payload)
  if not (crypto_data) then
    return nil, err or "No CRYPTO frame found"
  end
  local sni
  sni, err = extract_sni_from_crypto(crypto_data)
  if not (sni) then
    return nil, err or "No SNI found"
  end
  return sni, "SNI extracted successfully"
end.extract_sni
return {
  extract_sni = extract_sni,
  parse_initial_header = parse_initial_header
}
