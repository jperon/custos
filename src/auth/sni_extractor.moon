-- src/auth/sni_extractor.moon
-- Extracteur de SNI (Server Name Indication) depuis TLS ClientHello.
-- Parse RFC 5246 (TLS 1.2) et RFC 6066 (SNI extension).
-- Retourne le hostname SNI ou nil si absent/invalide.

{ :log_debug, :log_warn } = require "log"

--- Parse un entier 16-bit big-endian depuis un buffer à l'offset donné.
-- @tparam string buf Buffer octets
-- @tparam number offset Position (1-indexed)
-- @treturn number Valeur 16-bit ou 0 si offset invalide
read_u16_be = (buf, offset) ->
  unless buf and offset and offset > 0 and offset + 1 <= #buf
    return 0
  byte1 = buf\byte offset
  byte2 = buf\byte offset + 1
  (byte1 * 256) + byte2

--- Parse un entier 24-bit big-endian.
read_u24_be = (buf, offset) ->
  unless buf and offset and offset > 0 and offset + 2 <= #buf
    return 0
  byte1 = buf\byte offset
  byte2 = buf\byte offset + 1
  byte3 = buf\byte offset + 2
  (byte1 * 65536) + (byte2 * 256) + byte3

--- Parse un entier 8-bit.
read_u8 = (buf, offset) ->
  unless buf and offset and offset > 0 and offset <= #buf
    return 0
  buf\byte offset

--- Extrait le SNI hostname depuis un buffer TLS ClientHello brut.
-- Structure TLS (RFC 5246) :
--   Byte 0 : type (0x16 = Handshake)
--   Bytes 1-2 : version (ex: 0x0303 pour TLS 1.2)
--   Bytes 3-4 : length (big-endian)
--   [Handshake data...]
--
-- Handshake structure :
--   Byte 0 : msg_type (0x01 = ClientHello)
--   Bytes 1-3 : length (24-bit big-endian)
--   Bytes 4-5 : version
--   Bytes 6-37 : random (32 bytes)
--   Byte 38 : session_id_length
--   [session_id...]
--   [cipher_suites...]
--   [compression_methods...]
--   [extensions...]
--
-- Extension SNI (RFC 6066) type 0:
--   Bytes 0-1 : extension_type (0x0000)
--   Bytes 2-3 : extension_length
--   [extension_data with server_name_list]
--
-- @tparam string data Buffer octets brut (flux TLS)
-- @treturn string|nil Hostname SNI ou nil si absent/invalide
extract_sni = (data) ->
  unless data and #data >= 43
    log_debug { action: "server_sni_extract_too_short", len: #data or 0 }
    return nil

  -- Vérifier type record TLS = Handshake (0x16)
  record_type = read_u8 data, 1
  unless record_type == 0x16
    log_debug { action: "server_sni_extract_not_handshake", type: record_type }
    return nil

  -- Lire longueur du record (bytes 3-4)
  record_length = read_u16_be data, 3

  -- Vérifier que le buffer contient le record complet
  unless #data >= 5 + record_length
    log_debug { action: "server_sni_extract_truncated_record", avail: #data, need: 5 + record_length }
    return nil

  -- Offset 5 : début du handshake
  hs_offset = 5

  -- Handshake type = ClientHello (0x01)
  hs_type = read_u8 data, hs_offset + 1
  unless hs_type == 0x01
    log_debug { action: "server_sni_extract_not_clienthello", hs_type: hs_type }
    return nil

  -- Handshake length (24-bit, bytes 2-4 du handshake)
  hs_length = read_u24_be data, hs_offset + 2

  -- Offset 5 + 1 + 3 = 9 : début de ClientHello (version)
  ch_offset = hs_offset + 5

  -- ClientHello version (bytes 0-1, offset 0-1 within ClientHello)
  ch_version = read_u16_be data, ch_offset

  -- Random (32 bytes) : offset 2-33
  -- Session ID : 1 byte length at offset 34, then variable
  session_id_len = read_u8 data, ch_offset + 34

  -- Cipher suites : 2-byte length at offset 35 + session_id_len
  cipher_suites_offset = ch_offset + 35 + session_id_len
  unless cipher_suites_offset + 1 <= #data
    log_debug { action: "server_sni_extract_truncated_cipher_suites" }
    return nil

  cipher_suites_len = read_u16_be data, cipher_suites_offset

  -- Compression methods : 1-byte length at offset cipher_suites_offset + 2 + cipher_suites_len
  compression_offset = cipher_suites_offset + 2 + cipher_suites_len
  unless compression_offset + 1 <= #data
    log_debug { action: "server_sni_extract_truncated_compression" }
    return nil

  compression_len = read_u8 data, compression_offset

  -- Extensions : commencent à offset compression_offset + 1 + compression_len
  extensions_offset = compression_offset + 1 + compression_len

  -- Extensions length (2-byte, peut ne pas exister en TLS 1.0)
  unless extensions_offset + 1 <= #data
    log_debug { action: "server_sni_extract_no_extensions" }
    return nil

  extensions_len = read_u16_be data, extensions_offset
  unless extensions_len > 0
    log_debug { action: "server_sni_extract_empty_extensions" }
    return nil

  -- Début des extensions
  ext_data_offset = extensions_offset + 2
  ext_data_end = ext_data_offset + extensions_len

  unless ext_data_end <= #data
    log_debug { action: "server_sni_extract_truncated_extensions" }
    return nil

  -- Parser les extensions
  pos = ext_data_offset
  while pos < ext_data_end
    unless pos + 3 <= #data
      break

    ext_type = read_u16_be data, pos
    ext_len = read_u16_be data, pos + 2
    ext_payload_offset = pos + 4

    -- Extension SNI : type 0x0000
    if ext_type == 0x0000
      -- Extension data : server_name_list (2-byte length)
      unless ext_payload_offset + 1 <= #data
        log_debug { action: "server_sni_extract_snl_truncated" }
        return nil

      snl_len = read_u16_be data, ext_payload_offset

      -- Server name entries : name_type (1 byte) + name_length (2 bytes) + name (variable)
      snl_offset = ext_payload_offset + 2

      -- Lire le premier server_name (le reste est ignoré)
      unless snl_offset + 2 <= #data
        log_debug { action: "server_sni_extract_sn_header_truncated" }
        return nil

      name_type = read_u8 data, snl_offset
      name_len = read_u16_be data, snl_offset + 1

      -- name_type = 0 pour "host_name"
      unless name_type == 0
        log_debug { action: "server_sni_extract_unknown_name_type", type: name_type }
        return nil

      name_offset = snl_offset + 3
      unless name_offset + name_len - 1 <= #data
        log_debug { action: "server_sni_extract_sn_name_truncated", need: name_offset + name_len, have: #data }
        return nil

      -- Extraire le hostname
      hostname = data\sub name_offset, name_offset + name_len - 1

      -- Vérifier que c'est du texte valide (ASCII)
      unless hostname\match "^[a-zA-Z0-9._*-]+$"
        log_warn { action: "server_sni_extract_invalid_hostname", hostname: hostname }
        return nil

      log_debug { action: "server_sni_extract_found", hostname: hostname }
      return hostname

    -- Passer à l'extension suivante
    pos = ext_payload_offset + ext_len

  log_debug { action: "server_sni_extract_no_sni_extension" }
  nil

{ :extract_sni }
