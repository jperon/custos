local decrypt = require("ipparse.l4.quic.decrypt")
local frames = require("ipparse.l4.quic.frames")
local bin2hex, hex2bin
do
  local _obj_0 = require("ipparse.init")
  bin2hex, hex2bin = _obj_0.bin2hex, _obj_0.hex2bin
end
local su
su = string.unpack
local QuicL7Parser
do
  local _class_0
  local _base_0 = {
    extract_tls_data = function(self, crypto_frames)
      table.sort(crypto_frames, function(a, b)
        return a.offset < b.offset
      end)
      local tls_data = ""
      local expected_offset = 0
      for _index_0 = 1, #crypto_frames do
        local frame = crypto_frames[_index_0]
        if frame.name == "CRYPTO" and frame.data then
          if frame.offset == expected_offset then
            tls_data = tls_data .. frame.data
            expected_offset = expected_offset + #frame.data
            print("  Added CRYPTO frame: offset " .. tostring(frame.offset) .. ", length " .. tostring(#frame.data))
          elseif frame.offset > expected_offset then
            print("  Gap detected: expected offset " .. tostring(expected_offset) .. ", got " .. tostring(frame.offset))
            tls_data = tls_data .. frame.data
            expected_offset = frame.offset + #frame.data
          else
            print("  Overlapping CRYPTO frame ignored: offset " .. tostring(frame.offset))
          end
        end
      end
      print("Combined TLS data length: " .. tostring(#tls_data) .. " bytes")
      return tls_data
    end,
    parse_tls_handshake = function(self, tls_data)
      if #tls_data == 0 then
        return { }
      end
      local handshake_messages = { }
      local offset = 1
      while offset <= #tls_data do
        if offset + 5 > #tls_data then
          break
        end
        local content_type = su("B", tls_data, offset)
        local version = su(">H", tls_data, offset + 1)
        local length = su(">H", tls_data, offset + 3)
        print("  TLS Record: type=" .. tostring(content_type) .. ", version=0x" .. tostring(string.format("%04x", version)) .. ", length=" .. tostring(length))
        if offset + 4 + length > #tls_data then
          print("  Incomplete TLS record, stopping (offset=" .. tostring(offset) .. ", length=" .. tostring(length) .. ", total_data=" .. tostring(#tls_data) .. ")")
          break
        end
        local record_data = tls_data:sub(offset + 5, offset + 4 + length)
        if content_type == 0x16 then
          self:parse_handshake_messages(record_data, handshake_messages)
        end
        offset = offset + (5 + length)
      end
      print("Parsed " .. tostring(#handshake_messages) .. " TLS handshake messages")
      return handshake_messages
    end,
    parse_handshake_messages = function(self, record_data, messages)
      local offset = 1
      while offset <= #record_data do
        if offset + 4 > #record_data then
          break
        end
        local msg_type = su("B", record_data, offset)
        local msg_length = su(">I4", "\0" .. record_data:sub(offset + 1, offset + 3))
        print("    Handshake message: type=" .. tostring(msg_type) .. ", length=" .. tostring(msg_length))
        if offset + 4 + msg_length > #record_data then
          print("    Incomplete handshake message, stopping (offset=" .. tostring(offset) .. ", msg_length=" .. tostring(msg_length) .. ", record_data=" .. tostring(#record_data) .. ")")
          break
        end
        local msg_data = record_data:sub(offset + 4, offset + 3 + msg_length)
        local message = {
          type = msg_type,
          length = msg_length,
          data = msg_data,
          name = self:get_handshake_message_name(msg_type)
        }
        messages[#messages + 1] = message
        print("    → " .. tostring(message.name))
        offset = offset + (4 + msg_length)
      end
    end,
    get_handshake_message_name = function(self, msg_type)
      local message_names = {
        [1] = "ClientHello",
        [2] = "ServerHello",
        [4] = "NewSessionTicket",
        [8] = "EncryptedExtensions",
        [11] = "Certificate",
        [13] = "CertificateRequest",
        [15] = "CertificateVerify",
        [20] = "Finished"
      }
      return message_names[msg_type] or "Unknown(" .. tostring(msg_type) .. ")"
    end,
    extract_sni_from_client_hello = function(self, client_hello)
      if not (client_hello.type == 1) then
        return nil
      end
      local data = client_hello.data
      if #data < 38 then
        return nil
      end
      local offset = 1
      offset = offset + 34
      if offset > #data then
        return nil
      end
      local session_id_len = su("B", data, offset)
      offset = offset + (1 + session_id_len)
      if offset + 1 > #data then
        return nil
      end
      local cipher_suites_len = su(">H", data, offset)
      offset = offset + (2 + cipher_suites_len)
      if offset > #data then
        return nil
      end
      local compression_len = su("B", data, offset)
      offset = offset + (1 + compression_len)
      if offset + 1 > #data then
        return nil
      end
      local extensions_len = su(">H", data, offset)
      offset = offset + 2
      local extensions_end = offset + extensions_len - 1
      while offset < extensions_end do
        if offset + 3 > #data then
          return nil
        end
        local ext_type = su(">H", data, offset)
        local ext_len = su(">H", data, offset + 2)
        offset = offset + 4
        if ext_type == 0 then
          return self:parse_sni_extension(data:sub(offset, offset + ext_len - 1))
        end
        offset = offset + ext_len
      end
      return nil
    end,
    parse_sni_extension = function(self, ext_data)
      if #ext_data < 5 then
        return nil
      end
      print("    Parsing SNI extension data (" .. tostring(#ext_data) .. " bytes): " .. tostring(bin2hex(ext_data)))
      local offset = 1
      local list_len = su(">H", ext_data, offset)
      offset = offset + 2
      print("    Server name list length: " .. tostring(list_len))
      if offset > #ext_data then
        return nil
      end
      local name_type = su("B", ext_data, offset)
      offset = offset + 1
      print("    Name type: " .. tostring(name_type) .. " (should be 0 for hostname)")
      if not (name_type == 0) then
        return nil
      end
      if offset + 1 > #ext_data then
        return nil
      end
      local name_len = su(">H", ext_data, offset)
      offset = offset + 2
      print("    Hostname length: " .. tostring(name_len))
      if offset + name_len > #ext_data + 1 then
        return nil
      end
      local hostname = ext_data:sub(offset, offset + name_len - 1)
      print("    Found SNI: " .. tostring(hostname))
      return hostname
    end,
    process_frames = function(self, frames_array)
      local crypto_frames = { }
      for _index_0 = 1, #frames_array do
        local frame = frames_array[_index_0]
        if frame.name == "CRYPTO" then
          crypto_frames[#crypto_frames + 1] = frame
        end
      end
      if #crypto_frames == 0 then
        return nil
      end
      print("Processing " .. tostring(#crypto_frames) .. " CRYPTO frames")
      local tls_data = self:extract_tls_data(crypto_frames)
      local handshake_messages = self:parse_tls_handshake(tls_data)
      for _index_0 = 1, #handshake_messages do
        local message = handshake_messages[_index_0]
        if message.name == "ClientHello" then
          local sni = self:extract_sni_from_client_hello(message)
          if sni then
            self.sni_extracted = sni
            return sni
          end
        end
      end
      return nil
    end
  }
  _base_0.__index = _base_0
  _class_0 = setmetatable({
    __init = function(self)
      self.tls_buffer = ""
      self.handshake_complete = false
      self.sni_extracted = nil
      return print("QuicL7Parser initialized")
    end,
    __base = _base_0,
    __name = "QuicL7Parser"
  }, {
    __index = _base_0,
    __call = function(cls, ...)
      local _self_0 = setmetatable({}, _base_0)
      cls.__init(_self_0, ...)
      return _self_0
    end
  })
  _base_0.__class = _class_0
  QuicL7Parser = _class_0
end
local extract_quic_sni
extract_quic_sni = function(connection_id, packets)
  local decryption_results = decrypt.decrypt_quic_packets(connection_id, packets)
  local all_frames = { }
  for _index_0 = 1, #decryption_results do
    local result = decryption_results[_index_0]
    if result.success then
      local _list_0 = result.frames
      for _index_1 = 1, #_list_0 do
        local frame = _list_0[_index_1]
        all_frames[#all_frames + 1] = frame
      end
    end
  end
  local l7_parser = QuicL7Parser()
  return l7_parser:process_frames(all_frames)
end
return {
  QuicL7Parser = QuicL7Parser,
  extract_quic_sni = extract_quic_sni
}
