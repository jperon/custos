local log_debug, log_warn
do
  local _obj_0 = require("log")
  log_debug, log_warn = _obj_0.log_debug, _obj_0.log_warn
end
local ipparse_tls_client_hello = require("ipparse.l7.tls.handshake.client_hello")
local ipparse_tls_extension = require("ipparse.l7.tls.handshake.extension")
local ipparse_server_name = require("ipparse.l7.tls.handshake.extension.server_name")
local read_u16_be
read_u16_be = function(buf, offset)
  if not (buf and offset and offset > 0 and offset + 1 <= #buf) then
    return 0
  end
  return (buf:byte(offset) * 256) + buf:byte(offset + 1)
end
local valid_hostname
valid_hostname = function(hostname)
  return hostname and hostname:match("^[a-zA-Z0-9._*-]+$")
end
local extract_sni
extract_sni = function(data)
  if not (data and #data >= 9) then
    log_debug({
      action = "server_sni_extract_too_short",
      len = #data or 0
    })
    return nil
  end
  local record_type = data:byte(1)
  if not (record_type == 0x16) then
    log_debug({
      action = "server_sni_extract_not_handshake",
      type = record_type
    })
    return nil
  end
  local record_length = read_u16_be(data, 4)
  if not (#data >= 5 + record_length) then
    log_debug({
      action = "server_sni_extract_truncated_record",
      avail = #data,
      need = 5 + record_length
    })
    return nil
  end
  local hs_type = data:byte(6)
  if not (hs_type == 0x01) then
    log_debug({
      action = "server_sni_extract_not_clienthello",
      hs_type = hs_type
    })
    return nil
  end
  local ok_ch, ch = pcall(function()
    return ipparse_tls_client_hello.parse(data, 10)
  end)
  if not (ok_ch and ch and ch.extensions and #ch.extensions > 0) then
    log_debug({
      action = "server_sni_extract_clienthello_parse_failed"
    })
    return nil
  end
  local ext_data = ch.extensions
  local ext_offset = 1
  while ext_offset <= #ext_data do
    local ok_ext, ext, next_offset = pcall(function()
      return ipparse_tls_extension.parse(ext_data, ext_offset)
    end)
    if not (ok_ext and ext and next_offset and next_offset > ext_offset) then
      log_debug({
        action = "server_sni_extract_truncated_extensions"
      })
      return nil
    end
    if ext.type == 0 then
      if not (ext.data and #ext.data >= 5) then
        log_debug({
          action = "server_sni_extract_sni_parse_failed"
        })
        return nil
      end
      local name_list_len = read_u16_be(ext.data, 1)
      local name_type = ext.data:byte(3)
      local name_len = read_u16_be(ext.data, 4)
      local name_start = 6
      local name_end = name_start + name_len - 1
      if not (name_list_len >= 3 and #ext.data >= 2 + name_list_len) then
        log_debug({
          action = "server_sni_extract_sni_parse_failed"
        })
        return nil
      end
      if not (name_type == 0) then
        log_debug({
          action = "server_sni_extract_sni_parse_failed"
        })
        return nil
      end
      if not (name_len > 0 and name_end <= #ext.data and name_end <= 2 + name_list_len) then
        log_debug({
          action = "server_sni_extract_sni_parse_failed"
        })
        return nil
      end
      local ok_sni, sni_list = pcall(function()
        return ipparse_server_name.parse(ext.data, 1)
      end)
      if ok_sni and sni_list and sni_list.name and valid_hostname(sni_list.name) then
        log_debug({
          action = "server_sni_extract_found",
          hostname = sni_list.name
        })
        return sni_list.name
      end
      if ok_sni and sni_list and sni_list.name and not valid_hostname(sni_list.name) then
        log_warn({
          action = "server_sni_extract_invalid_hostname",
          hostname = sni_list.name
        })
        return nil
      end
      log_debug({
        action = "server_sni_extract_sni_parse_failed"
      })
      return nil
    end
    ext_offset = next_offset
  end
  log_debug({
    action = "server_sni_extract_no_sni_extension"
  })
  return nil
end
return {
  extract_sni = extract_sni
}
