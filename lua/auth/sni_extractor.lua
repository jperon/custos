local log_debug, log_warn
do
  local _obj_0 = require("log")
  log_debug, log_warn = _obj_0.log_debug, _obj_0.log_warn
end
local read_u16_be
read_u16_be = function(buf, offset)
  if not (buf and offset and offset > 0 and offset + 1 <= #buf) then
    return 0
  end
  local byte1 = buf:byte(offset)
  local byte2 = buf:byte(offset + 1)
  return (byte1 * 256) + byte2
end
local read_u24_be
read_u24_be = function(buf, offset)
  if not (buf and offset and offset > 0 and offset + 2 <= #buf) then
    return 0
  end
  local byte1 = buf:byte(offset)
  local byte2 = buf:byte(offset + 1)
  local byte3 = buf:byte(offset + 2)
  return (byte1 * 65536) + (byte2 * 256) + byte3
end
local read_u8
read_u8 = function(buf, offset)
  if not (buf and offset and offset > 0 and offset <= #buf) then
    return 0
  end
  return buf:byte(offset)
end
local extract_sni
extract_sni = function(data)
  if not (data and #data >= 43) then
    log_debug({
      action = "server_sni_extract_too_short",
      len = #data or 0
    })
    return nil
  end
  local record_type = read_u8(data, 1)
  if not (record_type == 0x16) then
    log_debug({
      action = "server_sni_extract_not_handshake",
      type = record_type
    })
    return nil
  end
  local record_length = read_u16_be(data, 3)
  if not (#data >= 5 + record_length) then
    log_debug({
      action = "server_sni_extract_truncated_record",
      avail = #data,
      need = 5 + record_length
    })
    return nil
  end
  local hs_offset = 5
  local hs_type = read_u8(data, hs_offset + 1)
  if not (hs_type == 0x01) then
    log_debug({
      action = "server_sni_extract_not_clienthello",
      hs_type = hs_type
    })
    return nil
  end
  local hs_length = read_u24_be(data, hs_offset + 2)
  local ch_offset = hs_offset + 5
  local ch_version = read_u16_be(data, ch_offset)
  local session_id_len = read_u8(data, ch_offset + 34)
  local cipher_suites_offset = ch_offset + 35 + session_id_len
  if not (cipher_suites_offset + 1 <= #data) then
    log_debug({
      action = "server_sni_extract_truncated_cipher_suites"
    })
    return nil
  end
  local cipher_suites_len = read_u16_be(data, cipher_suites_offset)
  local compression_offset = cipher_suites_offset + 2 + cipher_suites_len
  if not (compression_offset + 1 <= #data) then
    log_debug({
      action = "server_sni_extract_truncated_compression"
    })
    return nil
  end
  local compression_len = read_u8(data, compression_offset)
  local extensions_offset = compression_offset + 1 + compression_len
  if not (extensions_offset + 1 <= #data) then
    log_debug({
      action = "server_sni_extract_no_extensions"
    })
    return nil
  end
  local extensions_len = read_u16_be(data, extensions_offset)
  if not (extensions_len > 0) then
    log_debug({
      action = "server_sni_extract_empty_extensions"
    })
    return nil
  end
  local ext_data_offset = extensions_offset + 2
  local ext_data_end = ext_data_offset + extensions_len
  if not (ext_data_end <= #data) then
    log_debug({
      action = "server_sni_extract_truncated_extensions"
    })
    return nil
  end
  local pos = ext_data_offset
  while pos < ext_data_end do
    if not (pos + 3 <= #data) then
      break
    end
    local ext_type = read_u16_be(data, pos)
    local ext_len = read_u16_be(data, pos + 2)
    local ext_payload_offset = pos + 4
    if ext_type == 0x0000 then
      if not (ext_payload_offset + 1 <= #data) then
        log_debug({
          action = "server_sni_extract_snl_truncated"
        })
        return nil
      end
      local snl_len = read_u16_be(data, ext_payload_offset)
      local snl_offset = ext_payload_offset + 2
      if not (snl_offset + 2 <= #data) then
        log_debug({
          action = "server_sni_extract_sn_header_truncated"
        })
        return nil
      end
      local name_type = read_u8(data, snl_offset)
      local name_len = read_u16_be(data, snl_offset + 1)
      if not (name_type == 0) then
        log_debug({
          action = "server_sni_extract_unknown_name_type",
          type = name_type
        })
        return nil
      end
      local name_offset = snl_offset + 3
      if not (name_offset + name_len - 1 <= #data) then
        log_debug({
          action = "server_sni_extract_sn_name_truncated",
          need = name_offset + name_len,
          have = #data
        })
        return nil
      end
      local hostname = data:sub(name_offset, name_offset + name_len - 1)
      if not (hostname:match("^[a-zA-Z0-9._*-]+$")) then
        log_warn({
          action = "server_sni_extract_invalid_hostname",
          hostname = hostname
        })
        return nil
      end
      log_debug({
        action = "server_sni_extract_found",
        hostname = hostname
      })
      return hostname
    end
    pos = ext_payload_offset + ext_len
  end
  log_debug({
    action = "server_sni_extract_no_sni_extension"
  })
  return nil
end
return {
  extract_sni = extract_sni
}
