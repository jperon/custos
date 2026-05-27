-- src/auth/sni_extractor.moon
-- Extracteur SNI basé sur les parseurs TLS de ipparse.

{ :log_debug, :log_warn } = require "log"
ipparse_tls_client_hello = require "ipparse.l7.tls.handshake.client_hello"
ipparse_tls_extension = require "ipparse.l7.tls.handshake.extension"
ipparse_server_name = require "ipparse.l7.tls.handshake.extension.server_name"

read_u16_be = (buf, offset) ->
  return 0 unless buf and offset and offset > 0 and offset + 1 <= #buf
  (buf\byte(offset) * 256) + buf\byte(offset + 1)

valid_hostname = (hostname) ->
  hostname and hostname\match "^[a-zA-Z0-9._*-]+$"

extract_sni = (data) ->
  unless data and #data >= 9
    log_debug -> { action: "server_sni_extract_too_short", len: #data or 0 }
    return nil

  record_type = data\byte 1
  unless record_type == 0x16
    log_debug -> { action: "server_sni_extract_not_handshake", type: record_type }
    return nil

  record_length = read_u16_be data, 4
  unless #data >= 5 + record_length
    log_debug -> { action: "server_sni_extract_truncated_record", avail: #data, need: 5 + record_length }
    return nil

  hs_type = data\byte 6
  unless hs_type == 0x01
    log_debug -> { action: "server_sni_extract_not_clienthello", hs_type: hs_type }
    return nil

  -- ClientHello body starts after TLS record (5 bytes) + handshake header (4 bytes).
  ok_ch, ch = pcall -> ipparse_tls_client_hello.parse data, 10
  unless ok_ch and ch and ch.extensions and #ch.extensions > 0
    log_debug -> { action: "server_sni_extract_clienthello_parse_failed" }
    return nil

  ext_data = ch.extensions
  ext_offset = 1
  while ext_offset <= #ext_data
    ok_ext, ext, next_offset = pcall -> ipparse_tls_extension.parse ext_data, ext_offset
    unless ok_ext and ext and next_offset and next_offset > ext_offset
      log_debug -> { action: "server_sni_extract_truncated_extensions" }
      return nil

    if ext.type == 0
      unless ext.data and #ext.data >= 5
        log_debug -> { action: "server_sni_extract_sni_parse_failed" }
        return nil

      name_list_len = read_u16_be ext.data, 1
      name_type = ext.data\byte 3
      name_len = read_u16_be ext.data, 4
      name_start = 6
      name_end = name_start + name_len - 1

      unless name_list_len >= 3 and #ext.data >= 2 + name_list_len
        log_debug -> { action: "server_sni_extract_sni_parse_failed" }
        return nil
      unless name_type == 0
        log_debug -> { action: "server_sni_extract_sni_parse_failed" }
        return nil
      unless name_len > 0 and name_end <= #ext.data and name_end <= 2 + name_list_len
        log_debug -> { action: "server_sni_extract_sni_parse_failed" }
        return nil

      ok_sni, sni_list = pcall -> ipparse_server_name.parse ext.data, 1
      if ok_sni and sni_list and sni_list.name and valid_hostname sni_list.name
        log_debug -> { action: "server_sni_extract_found", hostname: sni_list.name }
        return sni_list.name
      if ok_sni and sni_list and sni_list.name and not valid_hostname sni_list.name
        log_warn -> { action: "server_sni_extract_invalid_hostname", hostname: sni_list.name }
        return nil
      log_debug -> { action: "server_sni_extract_sni_parse_failed" }
      return nil

    ext_offset = next_offset

  log_debug -> { action: "server_sni_extract_no_sni_extension" }
  nil

{ :extract_sni }
