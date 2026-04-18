local crypto = require("ipparse.l4.quic.crypto")
local aead = require("ipparse.lib.crypto.aead")
local frames = require("ipparse.l4.quic.frames")
local quic = require("ipparse.l4.quic")
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
local sp, su
do
  local _obj_0 = require("ipparse.lib.pack_compat")
  sp, su = _obj_0.pack, _obj_0.unpack
end
local QuicDecryptor
do
  local _class_0
  local _base_0 = {
    is_client_packet = function(self, packet_data)
      return true
    end,
    extract_sample = function(self, packet_data, payload_offset)
      local sample_offset = payload_offset + 4
      if sample_offset + 16 > #packet_data then
        error("Packet too short to extract header protection sample")
      end
      return packet_data:sub(sample_offset, sample_offset + 15)
    end,
    remove_header_protection = function(self, packet_data, is_client)
      if is_client == nil then
        is_client = true
      end
      if not (#packet_data >= 20) then
        error("Packet too short for QUIC Initial packet")
      end
      local first_byte = su("B", packet_data, 1)
      if not (band(first_byte, 0x80) ~= 0) then
        error("Expected long header packet")
      end
      local version = su(">I4", packet_data, 2)
      local dcid_len = su("B", packet_data, 6)
      local dcid = packet_data:sub(7, 6 + dcid_len)
      local scid_len = su("B", packet_data, 7 + dcid_len)
      local scid = packet_data:sub(8 + dcid_len, 7 + dcid_len + scid_len)
      local token_len_offset = 8 + dcid_len + scid_len
      local token_len, token_len_size = frames.parse_varint(packet_data, token_len_offset)
      local token_offset = token_len_offset + token_len_size
      local token = packet_data:sub(token_offset, token_offset + token_len - 1)
      local length_offset = token_offset + token_len
      local payload_length, length_size = frames.parse_varint(packet_data, length_offset)
      local payload_offset = length_offset + length_size
      local sample = self:extract_sample(packet_data, payload_offset)
      local hp_key = is_client and self.client_hp_key or self.server_hp_key
      local expected_pn = is_client and self.expected_client_pn or self.expected_server_pn
      local unprotected_header, recovered_pn = crypto.recover_quic_packet_number(packet_data:sub(1, payload_offset - 1), hp_key, sample, expected_pn, true)
      if is_client then
        self.expected_client_pn = recovered_pn + 1
      else
        self.expected_server_pn = recovered_pn + 1
      end
      return unprotected_header, recovered_pn, payload_offset
    end,
    decrypt_payload = function(self, packet_data, unprotected_header, packet_number, payload_offset, is_client)
      if is_client == nil then
        is_client = true
      end
      local encrypted_payload = packet_data:sub(payload_offset)
      local key = is_client and self.client_key or self.server_key
      local iv = is_client and self.client_iv or self.server_iv
      local decrypted_payload = aead.quic_decrypt_packet(key, iv, packet_number, encrypted_payload, unprotected_header)
      if not (decrypted_payload) then
        error("Failed to decrypt QUIC packet payload - authentication failed")
      end
      return decrypted_payload
    end,
    decrypt_initial_packet = function(self, packet_data)
      print("Decrypting QUIC Initial packet (" .. tostring(#packet_data) .. " bytes)")
      local is_client = self:is_client_packet(packet_data)
      local direction = is_client and "client->server" or "server->client"
      print("  Direction: " .. tostring(direction))
      local unprotected_header, packet_number, payload_offset = self:remove_header_protection(packet_data, is_client)
      print("  Recovered packet number: " .. tostring(packet_number))
      print("  Payload offset: " .. tostring(payload_offset))
      local decrypted_payload = self:decrypt_payload(packet_data, unprotected_header, packet_number, payload_offset, is_client)
      print("  Decrypted payload length: " .. tostring(#decrypted_payload) .. " bytes")
      local parsed_frames = { }
      for frame in frames.iter_frames(decrypted_payload) do
        parsed_frames[#parsed_frames + 1] = frame
        print("  Found " .. tostring(frame.name) .. " frame")
      end
      local valid, msg = frames.validate_frames(decrypted_payload)
      if not (valid) then
        print("  Warning: Frame validation failed: " .. tostring(msg))
      end
      local metadata = {
        packet_number = packet_number,
        is_client = is_client,
        direction = direction,
        payload_offset = payload_offset,
        unprotected_header = unprotected_header,
        decrypted_payload_length = #decrypted_payload,
        frame_count = #parsed_frames,
        keys_used = {
          key = bin2hex(is_client and self.client_key or self.server_key),
          iv = bin2hex(is_client and self.client_iv or self.server_iv),
          hp_key = bin2hex(is_client and self.client_hp_key or self.server_hp_key)
        }
      }
      return parsed_frames, metadata
    end
  }
  _base_0.__index = _base_0
  _class_0 = setmetatable({
    __init = function(self, connection_id)
      self.connection_id = connection_id
      self.client_secret, self.server_secret = crypto.derive_initial_secrets(connection_id)
      self.client_key, self.client_iv, self.client_hp_key = crypto.derive_packet_protection_keys(self.client_secret)
      self.server_key, self.server_iv, self.server_hp_key = crypto.derive_packet_protection_keys(self.server_secret)
      self.expected_client_pn = 0
      self.expected_server_pn = 0
      print("QuicDecryptor initialized for connection " .. tostring(bin2hex(connection_id)))
      print("  Client key: " .. tostring(bin2hex(self.client_key)))
      return print("  Server key: " .. tostring(bin2hex(self.server_key)))
    end,
    __base = _base_0,
    __name = "QuicDecryptor"
  }, {
    __index = _base_0,
    __call = function(cls, ...)
      local _self_0 = setmetatable({}, _base_0)
      cls.__init(_self_0, ...)
      return _self_0
    end
  })
  _base_0.__class = _class_0
  QuicDecryptor = _class_0
end
local decrypt_quic_initial
decrypt_quic_initial = function(connection_id, packet_data)
  local decryptor = QuicDecryptor(connection_id)
  return decryptor:decrypt_initial_packet(packet_data)
end
local decrypt_quic_packets
decrypt_quic_packets = function(connection_id, packets)
  local decryptor = QuicDecryptor(connection_id)
  local results = { }
  for i, packet_data in ipairs(packets) do
    print("\n=== Decrypting packet " .. tostring(i) .. " ===")
    local success, frames_or_error, metadata = pcall(function()
      return decryptor:decrypt_initial_packet(packet_data)
    end)
    if success then
      results[#results + 1] = {
        packet_index = i,
        frames = frames_or_error,
        metadata = metadata,
        success = true
      }
      print("✓ Packet " .. tostring(i) .. " decrypted successfully (" .. tostring(#frames_or_error) .. " frames)")
    else
      results[#results + 1] = {
        packet_index = i,
        error = frames_or_error,
        success = false
      }
      print("✗ Packet " .. tostring(i) .. " decryption failed: " .. tostring(frames_or_error))
    end
  end
  return results
end
return {
  QuicDecryptor = QuicDecryptor,
  decrypt_quic_initial = decrypt_quic_initial,
  decrypt_quic_packets = decrypt_quic_packets
}
