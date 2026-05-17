-- src/worker_tls.moon
-- Worker NFQUEUE pour l'enregistrement des SNI depuis TLS/QUIC.
-- Capture les paquets TCP/443 avec payload TLS (ClientHello) et UDP/443 (QUIC Initial),
-- extrait les SNI via ipparse, et enregistre les métadonnées enrichies (MAC, IPs, ports, protocole).

{ :ffi, :libc, :libnfq } = require "ffi_defs"
{ :run_queue, :NF_ACCEPT, :NF_DROP } = require "nfq_loop"
{ :get_l2 } = require "nfq/ethernet"
{ :log_allow, :log_block, :log_info, :log_warn, :log_error, :log_debug, :set_action_prefix } = require "log"
{ :user_for_mac } = require "auth.sessions"

-- ipparse modules for packet parsing and SNI extraction
ipparse_ip = require "ipparse.l3.ip"
ipparse_tcp = require "ipparse.l4.tcp"
ipparse_udp = require "ipparse.l4.udp"
ipparse_quic = require "ipparse.l4.quic"
ipparse_quic_session = require "ipparse.l7.quic.session"
ipparse_tls_client_hello = require "ipparse.l7.tls.handshake.client_hello"
ipparse_server_name = require "ipparse.l7.tls.handshake.extension.server_name"
ipparse_supported_versions = require "ipparse.l7.tls.handshake.extension.supported_versions"

bit = require "bit"
{ :nft } = require "config"
nft_cfg = nft or {}
SNI_TIMEOUT = nft_cfg.sni_timeout or nft_cfg.ip_timeout or "2m"

quic_sessions = {}
filter = nil
sni_policy = nil
cmd_for = nil
run_cmd = nil
events_wfd = nil

-- ── SNI Extraction Helpers ────────────────────────────────

tls_version_name = (ver) ->
  return nil unless ver
  switch ver
    when 0x0301 then "TLS1.0"
    when 0x0302 then "TLS1.1"
    when 0x0303 then "TLS1.2"
    when 0x0304 then "TLS1.3"
    else string.format("0x%04x", ver)

extract_supported_versions = (ext_data) ->
  return nil unless ext_data and #ext_data >= 2
  ok_sv, sv = pcall -> ipparse_supported_versions.parse ext_data, 1
  return nil unless ok_sv and sv

  if sv.versions and #sv.versions > 0
    best_ver = nil
    for ver in *sv.versions
      best_ver = ver if not best_ver or ver > best_ver
    return tls_version_name best_ver

  if sv.selected
    return tls_version_name sv.selected

  nil

--- Extract SNI from TLS ClientHello payload.
-- @tparam string payload Raw TLS record data starting with TLS record header
-- @treturn string|nil SNI hostname or nil
extract_sni_from_tls = (payload, ctx={}) ->
  tls_version = nil
  tls_record_version = nil
  tls_client_hello_version = nil
  tls_supported_version = nil
  if payload and #payload >= 5
    record_ver = payload\byte(2) * 256 + payload\byte(3)
    tls_record_version = tls_version_name record_ver
    tls_version = tls_record_version

  if payload and #payload >= 11
    ch_ver = payload\byte(10) * 256 + payload\byte(11)
    tls_client_hello_version = tls_version_name ch_ver
    tls_version = tls_client_hello_version or tls_version

  debug_tls = (action, extra=nil) ->
    e = {
      :action
      pkt_id: ctx.pkt_id
      tls_len: payload and #payload or 0
      tls_version: tls_version
      tls_record_version: tls_record_version
      tls_client_hello_version: tls_client_hello_version
      tls_supported_version: tls_supported_version
    }
    if extra
      for k, v in pairs extra
        e[k] = v
    log_debug e

  debug_tls "tls_parse_start"
  unless payload and #payload >= 9
    debug_tls "tls_parse_short_payload"
    return nil, "short_payload", { tls_version: tls_version, tls_parser_path: "none" }

  -- Verify TLS record type = Handshake (0x16)
  record_type = payload\byte 1
  unless record_type == 0x16
    debug_tls "tls_parse_not_handshake_record", { tls_record_type: string.format("0x%02x", record_type) }
    return nil, "not_handshake_record", { tls_version: tls_version, tls_parser_path: "none" }

  -- Handshake type = ClientHello (0x01) at offset 6
  hs_type = payload\byte 6
  unless hs_type == 0x01
    debug_tls "tls_parse_not_client_hello", { hs_type: string.format("0x%02x", hs_type) }
    return nil, "not_client_hello", { tls_version: tls_version, tls_parser_path: "none" }

  -- Try strict parse first (full ClientHello available in one packet)
  success, client_hello_parsed = pcall -> ipparse_tls_client_hello.parse payload, 6
  if success and client_hello_parsed and client_hello_parsed.extensions and #client_hello_parsed.extensions > 0
    if client_hello_parsed.version
      tls_client_hello_version = tls_version_name client_hello_parsed.version
      tls_version = tls_client_hello_version or tls_record_version

    -- Parse extensions field (format: 2-byte length + extension data)
    ext_data = client_hello_parsed.extensions
    if ext_data and #ext_data >= 2
      ext_list_len = (ext_data\byte 1) * 256 + ext_data\byte 2
      if #ext_data >= 2 + ext_list_len
        -- Parse individual extensions (skip 2-byte length header)
        ext_offset = 3
        ext_end = 2 + ext_list_len

        while ext_offset < ext_end and ext_offset + 3 <= #ext_data
          ext_type = (ext_data\byte ext_offset) * 256 + ext_data\byte(ext_offset + 1)
          ext_len = (ext_data\byte(ext_offset + 2)) * 256 + ext_data\byte(ext_offset + 3)
          ext_payload_offset = ext_offset + 4

          -- Extension type 0 = Server Name Indication
          if ext_type == 0 and ext_payload_offset + ext_len <= #ext_data
            sni_data = ext_data\sub ext_payload_offset, ext_payload_offset + ext_len - 1
            success_sni, sni_list = pcall -> ipparse_server_name.parse sni_data, 1
            if success_sni and sni_list and sni_list.name
              debug_tls "tls_parse_strict_sni_found", { sni: sni_list.name }
              return sni_list.name, nil, {
                tls_version: tls_version
                tls_record_version: tls_record_version
                tls_client_hello_version: tls_client_hello_version
                tls_supported_version: tls_supported_version
                tls_parser_path: "strict"
              }

          if ext_type == 0x002b and ext_payload_offset + ext_len <= #ext_data
            sv = extract_supported_versions ext_data\sub ext_payload_offset, ext_payload_offset + ext_len - 1
            if sv
              tls_supported_version = sv
              tls_version = tls_supported_version

          ext_offset = ext_payload_offset + ext_len

  -- Fallback parser tolerant to fragmented ClientHello packets.
  -- It only requires the prefix up to the SNI extension.
  offset = 10 -- TLS(5) + Handshake header(4) + Lua 1-indexing
  unless #payload >= offset + 33 -- version(2) + random(32)
    debug_tls "tls_parse_fallback_short_random"
    return nil, "fallback_short_random", {
      tls_version: tls_version
      tls_record_version: tls_record_version
      tls_client_hello_version: tls_client_hello_version
      tls_supported_version: tls_supported_version
      tls_parser_path: "fallback"
    }

  offset += 34
  session_id_len = payload\byte offset
  unless session_id_len
    debug_tls "tls_parse_fallback_no_session_id_len"
    return nil, "fallback_no_session_id_len", {
      tls_version: tls_version
      tls_record_version: tls_record_version
      tls_client_hello_version: tls_client_hello_version
      tls_supported_version: tls_supported_version
      tls_parser_path: "fallback"
    }
  offset += 1
  unless #payload >= offset + session_id_len - 1
    debug_tls "tls_parse_fallback_short_session_id", { session_id_len: session_id_len }
    return nil, "fallback_short_session_id", {
      tls_version: tls_version
      tls_record_version: tls_record_version
      tls_client_hello_version: tls_client_hello_version
      tls_supported_version: tls_supported_version
      tls_parser_path: "fallback"
    }
  offset += session_id_len

  unless #payload >= offset + 1
    debug_tls "tls_parse_fallback_short_cipher_len"
    return nil, "fallback_short_cipher_len", {
      tls_version: tls_version
      tls_record_version: tls_record_version
      tls_client_hello_version: tls_client_hello_version
      tls_supported_version: tls_supported_version
      tls_parser_path: "fallback"
    }
  cipher_suites_len = (payload\byte(offset) * 256) + payload\byte(offset + 1)
  offset += 2
  unless #payload >= offset + cipher_suites_len - 1
    debug_tls "tls_parse_fallback_short_cipher_suites", { cipher_suites_len: cipher_suites_len }
    return nil, "fallback_short_cipher_suites", {
      tls_version: tls_version
      tls_record_version: tls_record_version
      tls_client_hello_version: tls_client_hello_version
      tls_supported_version: tls_supported_version
      tls_parser_path: "fallback"
    }
  offset += cipher_suites_len

  unless #payload >= offset
    debug_tls "tls_parse_fallback_short_compression_len"
    return nil, "fallback_short_compression_len", {
      tls_version: tls_version
      tls_record_version: tls_record_version
      tls_client_hello_version: tls_client_hello_version
      tls_supported_version: tls_supported_version
      tls_parser_path: "fallback"
    }
  compression_len = payload\byte offset
  offset += 1
  unless #payload >= offset + compression_len - 1
    debug_tls "tls_parse_fallback_short_compression", { compression_len: compression_len }
    return nil, "fallback_short_compression", {
      tls_version: tls_version
      tls_record_version: tls_record_version
      tls_client_hello_version: tls_client_hello_version
      tls_supported_version: tls_supported_version
      tls_parser_path: "fallback"
    }
  offset += compression_len

  unless #payload >= offset + 1
    debug_tls "tls_parse_fallback_short_extensions_len"
    return nil, "fallback_short_extensions_len", {
      tls_version: tls_version
      tls_record_version: tls_record_version
      tls_client_hello_version: tls_client_hello_version
      tls_supported_version: tls_supported_version
      tls_parser_path: "fallback"
    }
  extensions_len = (payload\byte(offset) * 256) + payload\byte(offset + 1)
  offset += 2

  ext_end = math.min #payload, offset + extensions_len - 1
  while offset + 3 <= ext_end
    ext_type = (payload\byte(offset) * 256) + payload\byte(offset + 1)
    ext_len = (payload\byte(offset + 2) * 256) + payload\byte(offset + 3)
    ext_data_start = offset + 4
    ext_data_end = math.min ext_end, ext_data_start + ext_len - 1
    break if ext_data_start > ext_end

    if ext_type == 0 -- server_name
      unless ext_data_end - ext_data_start + 1 >= 5
        debug_tls "tls_parse_fallback_short_sni_ext"
        return nil, "fallback_short_sni_ext", {
          tls_version: tls_version
          tls_record_version: tls_record_version
          tls_client_hello_version: tls_client_hello_version
          tls_supported_version: tls_supported_version
          tls_parser_path: "fallback"
        }
      name_list_len = (payload\byte(ext_data_start) * 256) + payload\byte(ext_data_start + 1)
      name_type = payload\byte(ext_data_start + 2)
      name_len = (payload\byte(ext_data_start + 3) * 256) + payload\byte(ext_data_start + 4)
      name_start = ext_data_start + 5
      name_end = name_start + name_len - 1

      if name_type == 0 and name_len > 0 and name_end <= ext_data_end and name_len <= name_list_len
        sni = payload\sub name_start, name_end
        debug_tls "tls_parse_fallback_sni_found", { sni: sni }
        return sni, nil, {
          tls_version: tls_version
          tls_record_version: tls_record_version
          tls_client_hello_version: tls_client_hello_version
          tls_supported_version: tls_supported_version
          tls_parser_path: "fallback"
        }

    if ext_type == 0x002b
      sv = extract_supported_versions payload\sub ext_data_start, ext_data_end
      if sv
        tls_supported_version = sv
        tls_version = tls_supported_version

    offset = ext_data_start + ext_len

  debug_tls "tls_parse_no_sni"
  nil, "no_sni_in_extensions", {
    tls_version: tls_version
    tls_record_version: tls_record_version
    tls_client_hello_version: tls_client_hello_version
    tls_supported_version: tls_supported_version
    tls_parser_path: "fallback"
  }

--- Extract SNI from QUIC Initial packet crypto data.
-- @tparam string quic_payload Raw QUIC data starting at L4 payload
-- @treturn string|nil SNI hostname or nil
extract_sni_from_quic = (quic_payload, session_key=nil) ->
  return nil, "short_payload", { quic_parser_path: "none" } unless quic_payload and #quic_payload >= 5

  success, quic_header = pcall -> ipparse_quic.parse quic_payload, 1
  unless success and quic_header
    return nil, "quic_header_parse_failed", { quic_parser_path: "none" }
  unless quic_header.long_header
    return nil, "quic_short_header", { quic_parser_path: "none" }
  unless quic_header.pkt_type == 0x00
    return nil, "quic_not_initial", { quic_parser_path: "none" }

  session = nil
  if session_key and quic_sessions[session_key]
    session = quic_sessions[session_key]
  else
    ok_session, session_or_err = pcall -> ipparse_quic_session.new!
    unless ok_session and session_or_err
      return nil, "quic_session_init_failed:#{session_or_err}", { quic_parser_path: "session" }
    session = session_or_err
    quic_sessions[session_key] = session if session_key

  ok_push, push_err = session\push quic_payload
  unless ok_push
    quic_sessions[session_key] = nil if session_key
    return nil, "quic_push_failed:#{push_err}", { quic_parser_path: "session" }

  sni = session\sni!
  if sni and #sni > 0
    quic_sessions[session_key] = nil if session_key
    return sni, nil, { quic_parser_path: "session" }
  nil, "quic_no_sni_in_crypto", { quic_parser_path: "session" }

quic_flow_key = (src_ip, dst_ip, src_port, dst_port) ->
  a = string.format "%s|%d", src_ip or "unknown", src_port or 0
  b = string.format "%s|%d", dst_ip or "unknown", dst_port or 0
  if a <= b
    "#{a}|#{b}"
  else
    "#{b}|#{a}"

--- Format MAC address for logging
-- @tparam string mac_raw 6-byte MAC address
-- @treturn string Formatted MAC like "aa:bb:cc:dd:ee:ff"
format_mac = (mac_raw) ->
  return "unknown" unless mac_raw and #mac_raw == 6
  b1 = mac_raw\byte 1
  b2 = mac_raw\byte 2
  b3 = mac_raw\byte 3
  b4 = mac_raw\byte 4
  b5 = mac_raw\byte 5
  b6 = mac_raw\byte 6
  string.format "%02x:%02x:%02x:%02x:%02x:%02x", b1, b2, b3, b4, b5, b6

--- Format IP address for logging
-- @tparam number version IP version (4 or 6)
-- @tparam string ip_raw Raw IP bytes
-- @treturn string Formatted IP address
format_ip = (version, ip_raw) ->
  return "unknown" unless ip_raw

  if version == 4
    b1 = ip_raw\byte 1
    b2 = ip_raw\byte 2
    b3 = ip_raw\byte 3
    b4 = ip_raw\byte 4
    return "unknown" unless b1 and b2 and b3 and b4
    string.format "%d.%d.%d.%d", b1, b2, b3, b4
  elseif version == 6
    -- Use ipparse helper
    ipparse_ip.ip2s ip_raw
  else
    "unknown"

tsv_field = (v) ->
  s = if v ~= nil then tostring v else ""
  if #s == 0 then "-" else s

write_sni_event = (decision, fields) ->
  return unless events_wfd
  line = table.concat({
    tostring os.time!
    tsv_field decision
    tsv_field fields.sni
    tsv_field fields.mac_src
    tsv_field fields.src_ip
    tsv_field fields.dst_ip
    tsv_field fields.vlan
    tsv_field fields.user
    tsv_field fields.af
    tsv_field fields.reason
    tsv_field fields.rule
  }, "\t") .. "\n"
  libc.write events_wfd, line, #line

normalize_sni = (sni) ->
  return nil unless sni and #sni > 0
  sni\lower!\gsub "%.+$", ""

protocol_in_scope = (policy, l4_proto) ->
  return false unless policy
  p = policy.protocols or "both"
  return true if p == "both"
  return l4_proto == "tcp" if p == "tcp-only"
  return l4_proto == "udp" if p == "quic-only"
  false

is_mail_ssl_port = (port) ->
  return true if port == 465  -- SMTPS
  return true if port == 587  -- STARTTLS (SMTP)
  return true if port == 993  -- IMAPS
  return true if port == 995  -- POP3S
  false

is_ipv6 = (ip) ->
  ip and ip\find ":", 1, true

safe_filter_decide = (req) ->
  return nil, "filter_unavailable", nil unless filter and filter.decide
  ok, allowed, reason, rule = pcall filter.decide, req
  return nil, "filter_decide_exception", nil unless ok
  allowed, reason, rule

ensure_nft_modules = ->
  unless cmd_for
    ok_cmd, nft_queue = pcall require, "nft_queue"
    return false, "nft_queue_require_failed" unless ok_cmd and nft_queue and nft_queue.cmd_for
    cmd_for = nft_queue.cmd_for

  unless run_cmd
    ok_nft, nft_mod = pcall require, "nft"
    return false, "nft_require_failed" unless ok_nft and nft_mod and nft_mod.run_cmd
    run_cmd = nft_mod.run_cmd

  true, nil

apply_nft_allow = (src_ip, dst_ip, mac, policy) ->
  ok_mods, mod_err = ensure_nft_modules!
  return false, mod_err unless ok_mods
  return false, "invalid_ip_pair" unless src_ip and dst_ip and src_ip != "unknown" and dst_ip != "unknown"
  return false, "family_mismatch" if is_ipv6(src_ip) != is_ipv6(dst_ip)

  ip_kind = if is_ipv6(dst_ip) then "ip6" else "ip4"
  mac_kind = if is_ipv6(dst_ip) then "mac6" else "mac4"
  cmds = {}

  ip_cmd = cmd_for ip_kind, src_ip, dst_ip, SNI_TIMEOUT
  if ip_cmd
    cmds[#cmds + 1] = ip_cmd
  else
    return false, "nft_cmd_build_failed"

  if mac and mac != "unknown" and mac != "00:00:00:00:00:00"
    mac_cmd = cmd_for mac_kind, mac, dst_ip, SNI_TIMEOUT
    cmds[#cmds + 1] = mac_cmd if mac_cmd

  ok, err = run_cmd table.concat(cmds, "\n"), { quiet: true }
  return true if ok
  return false, err or "nft_cmd_failed" if policy and policy.nft_failure_policy == "fail-closed"
  true, "nft_failed_fail_open"

-- ── Main Packet Handler ──────────────────────────────────

--- Main callback for SNI logger NFQUEUE.
-- Handles both TCP/443 (TLS) and UDP/443 (QUIC) packets.
handle_sni_packet = (qh_ptr, nfad, pkt_id) ->
  log_debug { action: "callback", pkt_id: pkt_id }

  -- 1. Extract L2 (MAC source)
  l2 = get_l2 nfad
  unless l2
    log_debug { action: "no_l2", pkt_id: pkt_id }
    return NF_ACCEPT

  -- 2. Extract payload
  payload_ptr = ffi.new "unsigned char*[1]"
  payload_len = libnfq.nfq_get_payload nfad, payload_ptr
  if payload_len <= 0
    log_debug { action: "no_payload", pkt_id: pkt_id }
    return NF_ACCEPT

  raw = ffi.string payload_ptr[0], payload_len

  -- 3. Parse IP header
  ip, err = ipparse_ip.parse raw, 1
  unless ip
    log_debug { action: "ip_parse_failed", pkt_id: pkt_id }
    return NF_ACCEPT

  -- 4. Determine protocol and extract SNI
  protocol_name = nil
  l4_proto = nil
  sni = nil
  src_port = nil
  dst_port = nil
  tls_reason = nil
  tls_meta = nil

  if ip.protocol == 6  -- TCP
    l4_proto = "tcp"
    -- Parse TCP header
    success, tcp = pcall -> ipparse_tcp.parse raw, ip.data_off
    unless success and tcp
      log_debug { action: "tcp_parse_failed", pkt_id: pkt_id }
      return NF_ACCEPT

    unless tcp.data_off and tcp.data_off >= 1
      log_debug { action: "tcp_data_off_invalid", pkt_id: pkt_id }
      return NF_ACCEPT

    src_port = tcp.spt
    dst_port = tcp.dpt
    protocol_name = if is_mail_ssl_port dst_port
      switch dst_port
        when 465 then "smtps"
        when 587 then "smtp_starttls"
        when 993 then "imaps"
        when 995 then "pop3s"
        else "mail_ssl"
    else "https"

    if tcp.data_off > #raw
      log_debug { action: "tcp_no_payload", pkt_id: pkt_id }
      return NF_ACCEPT

    -- Extract TLS ClientHello from TCP payload
    tls_payload = raw\sub tcp.data_off
    unless tls_payload and #tls_payload > 0
      log_debug { action: "tcp_no_payload", pkt_id: pkt_id }
      return NF_ACCEPT

    -- Ignore non-TLS records to reduce noisy "no_sni_found" logs.
    unless tls_payload\byte(1) == 0x16
      log_debug { action: "tcp_not_tls_handshake", pkt_id: pkt_id, tls_record_type: string.format("0x%02x", tls_payload\byte(1)) }
      return NF_ACCEPT

    sni, tls_reason, tls_meta = extract_sni_from_tls tls_payload, { pkt_id: pkt_id }

  elseif ip.protocol == 17  -- UDP
    l4_proto = "udp"
    -- Parse UDP header
    success, udp = pcall -> ipparse_udp.parse raw, ip.data_off
    unless success and udp
      log_debug { action: "udp_parse_failed", pkt_id: pkt_id }
      return NF_ACCEPT

    src_port = udp.spt
    dst_port = udp.dpt
    protocol_name = "quic"

    -- Extract SNI from QUIC payload
    if udp.data_off <= #raw
      quic_payload = raw\sub udp.data_off
      src_ip = format_ip ip.version, ip.src
      dst_ip = format_ip ip.version, ip.dst
      quic_session_key = quic_flow_key src_ip, dst_ip, src_port, dst_port
      sni, tls_reason, tls_meta = extract_sni_from_quic quic_payload, quic_session_key

  mac_str = format_mac l2.mac_raw
  ip_src_str = format_ip ip.version, ip.src
  ip_dst_str = format_ip ip.version, ip.dst
  af = if ip.version == 6 then "ipv6" else "ipv4"
  strict_mode = sni_policy and sni_policy.mode == "strict-443"
  in_scope = protocol_in_scope sni_policy, l4_proto
  mail_port = is_mail_ssl_port dst_port

  unless sni
    if protocol_name == "quic" and tls_reason and (
      tls_reason\match("^quic_session_init_failed") or tls_reason\match("^quic_push_failed")
    )
      log_warn {
        action: "quic_parse_failed"
        pkt_id: pkt_id
        reason: tls_reason
        quic_parser_path: tls_meta and tls_meta.quic_parser_path
      }
    if strict_mode and in_scope and not mail_port
      log_block {
        action: "sni_verdict_block_no_sni"
        pkt_id: pkt_id
        protocol: protocol_name
        l4_proto: l4_proto
        ip_src: ip_src_str
        ip_dst: ip_dst_str
        port_src: src_port
        port_dst: dst_port
        reason: tls_reason or "no_sni"
      }
      write_sni_event "block", {
        sni: nil
        mac_src: mac_str
        src_ip: ip_src_str
        dst_ip: ip_dst_str
        vlan: l2.vlan
        user: nil
        af: af
        reason: tls_reason or "no_sni"
        rule: "strict-443/no_sni"
      }
      return NF_DROP
    if mail_port and strict_mode and in_scope
      log_warn {
        action: "sni_verdict_warn_no_sni_mail"
        pkt_id: pkt_id
        protocol: protocol_name
        l4_proto: l4_proto
        ip_src: ip_src_str
        ip_dst: ip_dst_str
        port_src: src_port
        port_dst: dst_port
        reason: tls_reason or "no_sni"
        tls_version: tls_meta and tls_meta.tls_version
        tls_record_version: tls_meta and tls_meta.tls_record_version
        tls_client_hello_version: tls_meta and tls_meta.tls_client_hello_version
        tls_supported_version: tls_meta and tls_meta.tls_supported_version
        tls_parser_path: tls_meta and tls_meta.tls_parser_path
      }
      write_sni_event "warn", {
        sni: nil
        mac_src: mac_str
        src_ip: ip_src_str
        dst_ip: ip_dst_str
        vlan: l2.vlan
        user: nil
        af: af
        reason: tls_reason or "no_sni"
        rule: "mail_ssl/no_sni"
      }
      return NF_ACCEPT
    log_debug {
      action: "sni_verdict_skip_no_sni", pkt_id: pkt_id, protocol: protocol_name, l4_proto: l4_proto, reason: tls_reason
      tls_version: tls_meta and tls_meta.tls_version
      tls_record_version: tls_meta and tls_meta.tls_record_version
      tls_client_hello_version: tls_meta and tls_meta.tls_client_hello_version
      tls_supported_version: tls_meta and tls_meta.tls_supported_version
      tls_parser_path: tls_meta and tls_meta.tls_parser_path
      quic_parser_path: tls_meta and tls_meta.quic_parser_path
    }
    return NF_ACCEPT

  sni_norm = normalize_sni sni
  log_info {
    action: "sni_captured"
    protocol: protocol_name
    l4_proto: l4_proto
    sni: sni_norm or sni
    mac_src: mac_str
    ip_src: ip_src_str
    ip_dst: ip_dst_str
    port_src: src_port
    port_dst: dst_port
    tls_version: tls_meta and tls_meta.tls_version
    tls_record_version: tls_meta and tls_meta.tls_record_version
    tls_client_hello_version: tls_meta and tls_meta.tls_client_hello_version
    tls_supported_version: tls_meta and tls_meta.tls_supported_version
    tls_parser_path: tls_meta and tls_meta.tls_parser_path
    quic_parser_path: tls_meta and tls_meta.quic_parser_path
  }

  req = {
    domain: sni_norm or sni
    src_ip: ip_src_str
    mac: mac_str
    vlan: l2.vlan
    ts: os.time!
    user: user_for_mac mac_str, ip_src_str, auth_sessions_file
  }
  allowed, decide_reason, decide_rule = safe_filter_decide req

  if not in_scope
    log_debug {
      action: "sni_verdict_skip_protocol"
      pkt_id: pkt_id
      protocol: protocol_name
      l4_proto: l4_proto
      sni: sni_norm or sni
      policy_protocols: sni_policy and sni_policy.protocols or "both"
    }
    return NF_ACCEPT

  if allowed == nil
    log_warn {
      action: "sni_verdict_skip_filter_error"
      pkt_id: pkt_id
      protocol: protocol_name
      l4_proto: l4_proto
      sni: sni_norm or sni
      reason: decide_reason or "filter_error"
    }
    return NF_ACCEPT

  if allowed == true
    ok_nft, nft_reason = apply_nft_allow ip_src_str, ip_dst_str, mac_str, sni_policy
    unless ok_nft
      log_block {
        action: "sni_verdict_nft_failed"
        pkt_id: pkt_id
        protocol: protocol_name
        l4_proto: l4_proto
        sni: sni_norm or sni
        ip_src: ip_src_str
        ip_dst: ip_dst_str
        mac_src: mac_str
        reason: nft_reason
        nft_failure_policy: sni_policy and sni_policy.nft_failure_policy or "fail-closed"
      }
      write_sni_event "block", {
        sni: sni_norm or sni
        mac_src: mac_str
        src_ip: ip_src_str
        dst_ip: ip_dst_str
        vlan: l2.vlan
        user: nil
        af: af
        reason: nft_reason
        rule: decide_rule or "nft_insert_failed"
      }
      return NF_DROP if (sni_policy and sni_policy.nft_failure_policy or "fail-closed") == "fail-closed"
      return NF_ACCEPT

    log_allow {
      action: "sni_verdict_allow"
      protocol: protocol_name
      l4_proto: l4_proto
      sni: sni_norm or sni
      ip_src: ip_src_str
      ip_dst: ip_dst_str
      mac_src: mac_str
      port_src: src_port
      port_dst: dst_port
      filter_reason: decide_reason
      rule: decide_rule
      nft_outcome: nft_reason or "ok"
      tls_version: tls_meta and tls_meta.tls_version
      tls_record_version: tls_meta and tls_meta.tls_record_version
      tls_client_hello_version: tls_meta and tls_meta.tls_client_hello_version
      tls_supported_version: tls_meta and tls_meta.tls_supported_version
      tls_parser_path: tls_meta and tls_meta.tls_parser_path
      quic_parser_path: tls_meta and tls_meta.quic_parser_path
    }
    write_sni_event "allow", {
      sni: sni_norm or sni
      mac_src: mac_str
      src_ip: ip_src_str
      dst_ip: ip_dst_str
      vlan: l2.vlan
      user: nil
      af: af
      reason: decide_reason
      rule: decide_rule
    }
    return NF_ACCEPT

  if allowed == "dnsonly"
    if strict_mode
      log_block {
        action: "sni_verdict_block_dnsonly"
        pkt_id: pkt_id
        protocol: protocol_name
        l4_proto: l4_proto
        sni: sni_norm or sni
        ip_src: ip_src_str
        ip_dst: ip_dst_str
        mac_src: mac_str
        reason: decide_reason or "dnsonly"
        rule: decide_rule
      }
      write_sni_event "block", {
        sni: sni_norm or sni
        mac_src: mac_str
        src_ip: ip_src_str
        dst_ip: ip_dst_str
        vlan: l2.vlan
        user: nil
        af: af
        reason: decide_reason or "dnsonly"
        rule: decide_rule or "dnsonly"
      }
      return NF_DROP
    log_debug {
      action: "sni_verdict_skip_dnsonly"
      pkt_id: pkt_id
      protocol: protocol_name
      l4_proto: l4_proto
      sni: sni_norm or sni
      reason: decide_reason or "dnsonly"
      rule: decide_rule
    }
    return NF_ACCEPT

  if strict_mode
    log_block {
      action: "sni_verdict_block"
      pkt_id: pkt_id
      protocol: protocol_name
      l4_proto: l4_proto
      sni: sni_norm or sni
      ip_src: ip_src_str
      ip_dst: ip_dst_str
      mac_src: mac_str
      reason: decide_reason or "denied"
      rule: decide_rule
    }
    write_sni_event "block", {
      sni: sni_norm or sni
      mac_src: mac_str
      src_ip: ip_src_str
      dst_ip: ip_dst_str
      vlan: l2.vlan
      user: nil
      af: af
      reason: decide_reason or "denied"
      rule: decide_rule
    }
    return NF_DROP

  log_debug {
    action: "sni_verdict_skip"
    pkt_id: pkt_id
    protocol: protocol_name
    l4_proto: l4_proto
    sni: sni_norm or sni
    reason: decide_reason or "denied"
    rule: decide_rule
  }
  NF_ACCEPT

--- Entry point for the worker.
-- @tparam number queue_num Queue number
run = (queue_num, ev_wfd=nil, filter_data=nil) ->
  set_action_prefix "sni_log_"
  events_wfd = ev_wfd

  ok_filter, filter_or_err = pcall require, "filter"
  if ok_filter and filter_or_err
    filter = filter_or_err
    -- Initialize filter with data passed from main.moon
    if filter_data
      filter.rules = filter_data.rules
      filter.auth_cfg_cache = filter_data.auth_cfg_cache
      filter.decision_cfg = filter_data.decision_cfg
    auth_cfg = if filter.get_auth_cfg then filter.get_auth_cfg! else {}
    auth_sessions_file = auth_cfg.sessions_file or auth_sessions_file
    sni_policy = auth_cfg and auth_cfg.sni_verdict or {}
  else
    filter = nil
    sni_policy = {}
    log_warn { action: "filter_require_failed", err: tostring(filter_or_err) }
  sni_policy.enabled = if sni_policy.enabled == nil then true else not not sni_policy.enabled
  sni_policy.mode = sni_policy.mode or "strict-443"
  sni_policy.protocols = sni_policy.protocols or "both"
  sni_policy.nft_failure_policy = sni_policy.nft_failure_policy or "fail-closed"
  log_info { action: "starting", queue: queue_num }

  unless sni_policy.enabled
    log_info { action: "disabled", queue: queue_num }
    return run_queue tonumber(queue_num), (qh_ptr, nfad, pkt_id) -> NF_ACCEPT

  log_info {
    action: "policy_loaded"
    queue: queue_num
    mode: sni_policy.mode
    protocols: sni_policy.protocols
    nft_failure_policy: sni_policy.nft_failure_policy
  }
  run_queue tonumber(queue_num), handle_sni_packet

{ :run, :normalize_sni, :protocol_in_scope, :apply_nft_allow }
