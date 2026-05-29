local ffi, libc, libnfq
do
  local _obj_0 = require("ffi_defs")
  ffi, libc, libnfq = _obj_0.ffi, _obj_0.libc, _obj_0.libnfq
end
local run_queue, NF_ACCEPT, NF_DROP
do
  local _obj_0 = require("nfq_loop")
  run_queue, NF_ACCEPT, NF_DROP = _obj_0.run_queue, _obj_0.NF_ACCEPT, _obj_0.NF_DROP
end
local get_l2
get_l2 = require("nfq/ethernet").get_l2
local log_allow, log_block, log_info, log_warn, log_error, log_debug, set_action_prefix
do
  local _obj_0 = require("log")
  log_allow, log_block, log_info, log_warn, log_error, log_debug, set_action_prefix = _obj_0.log_allow, _obj_0.log_block, _obj_0.log_info, _obj_0.log_warn, _obj_0.log_error, _obj_0.log_debug, _obj_0.set_action_prefix
end
local user_for_mac
user_for_mac = require("auth.sessions").user_for_mac
local ipparse_ip = require("ipparse.l3.ip")
local ipparse_tcp = require("ipparse.l4.tcp")
local ipparse_udp = require("ipparse.l4.udp")
local ipparse_quic = require("ipparse.l4.quic")
local ipparse_quic_session = require("ipparse.l7.quic.session")
local ipparse_tls_client_hello = require("ipparse.l7.tls.handshake.client_hello")
local ipparse_server_name = require("ipparse.l7.tls.handshake.extension.server_name")
local ipparse_supported_versions = require("ipparse.l7.tls.handshake.extension.supported_versions")
local bit = require("bit")
local nft
nft = require("config").nft
local nft_cfg = nft or { }
local SNI_TIMEOUT = nft_cfg.sni_timeout or nft_cfg.ip_timeout or "2m"
local quic_sessions = { }
local filter = nil
local sni_policy = nil
local cmd_for = nil
local run_cmd = nil
local events_wfd = nil
local tls_version_name
tls_version_name = function(ver)
  if not (ver) then
    return nil
  end
  local _exp_0 = ver
  if 0x0301 == _exp_0 then
    return "TLS1.0"
  elseif 0x0302 == _exp_0 then
    return "TLS1.1"
  elseif 0x0303 == _exp_0 then
    return "TLS1.2"
  elseif 0x0304 == _exp_0 then
    return "TLS1.3"
  else
    return string.format("0x%04x", ver)
  end
end
local extract_supported_versions
extract_supported_versions = function(ext_data)
  if not (ext_data and #ext_data >= 2) then
    return nil
  end
  local ok_sv, sv = pcall(function()
    return ipparse_supported_versions.parse(ext_data, 1)
  end)
  if not (ok_sv and sv) then
    return nil
  end
  if sv.versions and #sv.versions > 0 then
    local best_ver = nil
    local _list_0 = sv.versions
    for _index_0 = 1, #_list_0 do
      local ver = _list_0[_index_0]
      if not best_ver or ver > best_ver then
        best_ver = ver
      end
    end
    return tls_version_name(best_ver)
  end
  if sv.selected then
    return tls_version_name(sv.selected)
  end
  return nil
end
local extract_sni_from_tls
extract_sni_from_tls = function(payload, ctx)
  if ctx == nil then
    ctx = { }
  end
  local tls_version = nil
  local tls_record_version = nil
  local tls_client_hello_version = nil
  local tls_supported_version = nil
  if payload and #payload >= 5 then
    local record_ver = payload:byte(2) * 256 + payload:byte(3)
    tls_record_version = tls_version_name(record_ver)
    tls_version = tls_record_version
  end
  if payload and #payload >= 11 then
    local ch_ver = payload:byte(10) * 256 + payload:byte(11)
    tls_client_hello_version = tls_version_name(ch_ver)
    tls_version = tls_client_hello_version or tls_version
  end
  local debug_tls
  debug_tls = function(action, extra)
    if extra == nil then
      extra = nil
    end
    local e = {
      action = action,
      pkt_id = ctx.pkt_id,
      tls_len = payload and #payload or 0,
      tls_version = tls_version,
      tls_record_version = tls_record_version,
      tls_client_hello_version = tls_client_hello_version,
      tls_supported_version = tls_supported_version
    }
    if extra then
      for k, v in pairs(extra) do
        e[k] = v
      end
    end
    return log_debug(function()
      return e
    end)
  end
  debug_tls("tls_parse_start")
  if not (payload and #payload >= 9) then
    debug_tls("tls_parse_short_payload")
    return nil, "short_payload", {
      tls_version = tls_version,
      tls_parser_path = "none"
    }
  end
  local record_type = payload:byte(1)
  if not (record_type == 0x16) then
    debug_tls("tls_parse_not_handshake_record", {
      tls_record_type = string.format("0x%02x", record_type)
    })
    return nil, "not_handshake_record", {
      tls_version = tls_version,
      tls_parser_path = "none"
    }
  end
  local hs_type = payload:byte(6)
  if not (hs_type == 0x01) then
    debug_tls("tls_parse_not_client_hello", {
      hs_type = string.format("0x%02x", hs_type)
    })
    return nil, "not_client_hello", {
      tls_version = tls_version,
      tls_parser_path = "none"
    }
  end
  local success, client_hello_parsed = pcall(function()
    return ipparse_tls_client_hello.parse(payload, 6)
  end)
  if success and client_hello_parsed and client_hello_parsed.extensions and #client_hello_parsed.extensions > 0 then
    if client_hello_parsed.version then
      tls_client_hello_version = tls_version_name(client_hello_parsed.version)
      tls_version = tls_client_hello_version or tls_record_version
    end
    local ext_data = client_hello_parsed.extensions
    if ext_data and #ext_data >= 2 then
      local ext_list_len = (ext_data:byte(1)) * 256 + ext_data:byte(2)
      if #ext_data >= 2 + ext_list_len then
        local ext_offset = 3
        local ext_end = 2 + ext_list_len
        while ext_offset < ext_end and ext_offset + 3 <= #ext_data do
          local ext_type = (ext_data:byte(ext_offset)) * 256 + ext_data:byte(ext_offset + 1)
          local ext_len = (ext_data:byte(ext_offset + 2)) * 256 + ext_data:byte(ext_offset + 3)
          local ext_payload_offset = ext_offset + 4
          if ext_type == 0 and ext_payload_offset + ext_len <= #ext_data then
            local sni_data = ext_data:sub(ext_payload_offset, ext_payload_offset + ext_len - 1)
            local success_sni, sni_list = pcall(function()
              return ipparse_server_name.parse(sni_data, 1)
            end)
            if success_sni and sni_list and sni_list.name then
              debug_tls("tls_parse_strict_sni_found", {
                sni = sni_list.name
              })
              return sni_list.name, nil, {
                tls_version = tls_version,
                tls_record_version = tls_record_version,
                tls_client_hello_version = tls_client_hello_version,
                tls_supported_version = tls_supported_version,
                tls_parser_path = "strict"
              }
            end
          end
          if ext_type == 0x002b and ext_payload_offset + ext_len <= #ext_data then
            local sv = extract_supported_versions(ext_data:sub(ext_payload_offset, ext_payload_offset + ext_len - 1))
            if sv then
              tls_supported_version = sv
              tls_version = tls_supported_version
            end
          end
          ext_offset = ext_payload_offset + ext_len
        end
      end
    end
  end
  local offset = 10
  if not (#payload >= offset + 33) then
    debug_tls("tls_parse_fallback_short_random")
    return nil, "fallback_short_random", {
      tls_version = tls_version,
      tls_record_version = tls_record_version,
      tls_client_hello_version = tls_client_hello_version,
      tls_supported_version = tls_supported_version,
      tls_parser_path = "fallback"
    }
  end
  offset = offset + 34
  local session_id_len = payload:byte(offset)
  if not (session_id_len) then
    debug_tls("tls_parse_fallback_no_session_id_len")
    return nil, "fallback_no_session_id_len", {
      tls_version = tls_version,
      tls_record_version = tls_record_version,
      tls_client_hello_version = tls_client_hello_version,
      tls_supported_version = tls_supported_version,
      tls_parser_path = "fallback"
    }
  end
  offset = offset + 1
  if not (#payload >= offset + session_id_len - 1) then
    debug_tls("tls_parse_fallback_short_session_id", {
      session_id_len = session_id_len
    })
    return nil, "fallback_short_session_id", {
      tls_version = tls_version,
      tls_record_version = tls_record_version,
      tls_client_hello_version = tls_client_hello_version,
      tls_supported_version = tls_supported_version,
      tls_parser_path = "fallback"
    }
  end
  offset = offset + session_id_len
  if not (#payload >= offset + 1) then
    debug_tls("tls_parse_fallback_short_cipher_len")
    return nil, "fallback_short_cipher_len", {
      tls_version = tls_version,
      tls_record_version = tls_record_version,
      tls_client_hello_version = tls_client_hello_version,
      tls_supported_version = tls_supported_version,
      tls_parser_path = "fallback"
    }
  end
  local cipher_suites_len = (payload:byte(offset) * 256) + payload:byte(offset + 1)
  offset = offset + 2
  if not (#payload >= offset + cipher_suites_len - 1) then
    debug_tls("tls_parse_fallback_short_cipher_suites", {
      cipher_suites_len = cipher_suites_len
    })
    return nil, "fallback_short_cipher_suites", {
      tls_version = tls_version,
      tls_record_version = tls_record_version,
      tls_client_hello_version = tls_client_hello_version,
      tls_supported_version = tls_supported_version,
      tls_parser_path = "fallback"
    }
  end
  offset = offset + cipher_suites_len
  if not (#payload >= offset) then
    debug_tls("tls_parse_fallback_short_compression_len")
    return nil, "fallback_short_compression_len", {
      tls_version = tls_version,
      tls_record_version = tls_record_version,
      tls_client_hello_version = tls_client_hello_version,
      tls_supported_version = tls_supported_version,
      tls_parser_path = "fallback"
    }
  end
  local compression_len = payload:byte(offset)
  offset = offset + 1
  if not (#payload >= offset + compression_len - 1) then
    debug_tls("tls_parse_fallback_short_compression", {
      compression_len = compression_len
    })
    return nil, "fallback_short_compression", {
      tls_version = tls_version,
      tls_record_version = tls_record_version,
      tls_client_hello_version = tls_client_hello_version,
      tls_supported_version = tls_supported_version,
      tls_parser_path = "fallback"
    }
  end
  offset = offset + compression_len
  if not (#payload >= offset + 1) then
    debug_tls("tls_parse_fallback_short_extensions_len")
    return nil, "fallback_short_extensions_len", {
      tls_version = tls_version,
      tls_record_version = tls_record_version,
      tls_client_hello_version = tls_client_hello_version,
      tls_supported_version = tls_supported_version,
      tls_parser_path = "fallback"
    }
  end
  local extensions_len = (payload:byte(offset) * 256) + payload:byte(offset + 1)
  offset = offset + 2
  local ext_end = math.min(#payload, offset + extensions_len - 1)
  while offset + 3 <= ext_end do
    local ext_type = (payload:byte(offset) * 256) + payload:byte(offset + 1)
    local ext_len = (payload:byte(offset + 2) * 256) + payload:byte(offset + 3)
    local ext_data_start = offset + 4
    local ext_data_end = math.min(ext_end, ext_data_start + ext_len - 1)
    if ext_data_start > ext_end then
      break
    end
    if ext_type == 0 then
      if not (ext_data_end - ext_data_start + 1 >= 5) then
        debug_tls("tls_parse_fallback_short_sni_ext")
        return nil, "fallback_short_sni_ext", {
          tls_version = tls_version,
          tls_record_version = tls_record_version,
          tls_client_hello_version = tls_client_hello_version,
          tls_supported_version = tls_supported_version,
          tls_parser_path = "fallback"
        }
      end
      local name_list_len = (payload:byte(ext_data_start) * 256) + payload:byte(ext_data_start + 1)
      local name_type = payload:byte(ext_data_start + 2)
      local name_len = (payload:byte(ext_data_start + 3) * 256) + payload:byte(ext_data_start + 4)
      local name_start = ext_data_start + 5
      local name_end = name_start + name_len - 1
      if name_type == 0 and name_len > 0 and name_end <= ext_data_end and name_len <= name_list_len then
        local sni = payload:sub(name_start, name_end)
        debug_tls("tls_parse_fallback_sni_found", {
          sni = sni
        })
        return sni, nil, {
          tls_version = tls_version,
          tls_record_version = tls_record_version,
          tls_client_hello_version = tls_client_hello_version,
          tls_supported_version = tls_supported_version,
          tls_parser_path = "fallback"
        }
      end
    end
    if ext_type == 0x002b then
      local sv = extract_supported_versions(payload:sub(ext_data_start, ext_data_end))
      if sv then
        tls_supported_version = sv
        tls_version = tls_supported_version
      end
    end
    offset = ext_data_start + ext_len
  end
  debug_tls("tls_parse_no_sni")
  return nil, "no_sni_in_extensions", {
    tls_version = tls_version,
    tls_record_version = tls_record_version,
    tls_client_hello_version = tls_client_hello_version,
    tls_supported_version = tls_supported_version,
    tls_parser_path = "fallback"
  }
end
local extract_sni_from_quic
extract_sni_from_quic = function(quic_payload, session_key)
  if session_key == nil then
    session_key = nil
  end
  if not (quic_payload and #quic_payload >= 5) then
    return nil, "short_payload", {
      quic_parser_path = "none"
    }
  end
  local success, quic_header = pcall(function()
    return ipparse_quic.parse(quic_payload, 1)
  end)
  if not (success and quic_header) then
    return nil, "quic_header_parse_failed", {
      quic_parser_path = "none"
    }
  end
  if not (quic_header.long_header) then
    return nil, "quic_short_header", {
      quic_parser_path = "none"
    }
  end
  if not (quic_header.pkt_type == 0x00) then
    return nil, "quic_not_initial", {
      quic_parser_path = "none"
    }
  end
  local session = nil
  if session_key and quic_sessions[session_key] then
    session = quic_sessions[session_key]
  else
    local ok_session, session_or_err = pcall(function()
      return ipparse_quic_session.new()
    end)
    if not (ok_session and session_or_err) then
      return nil, "quic_session_init_failed:" .. tostring(session_or_err), {
        quic_parser_path = "session"
      }
    end
    session = session_or_err
    if session_key then
      quic_sessions[session_key] = session
    end
  end
  local ok_push, push_err = session:push(quic_payload)
  if not (ok_push) then
    if session_key then
      quic_sessions[session_key] = nil
    end
    return nil, "quic_push_failed:" .. tostring(push_err), {
      quic_parser_path = "session"
    }
  end
  local sni = session:sni()
  if sni and #sni > 0 then
    if session_key then
      quic_sessions[session_key] = nil
    end
    return sni, nil, {
      quic_parser_path = "session"
    }
  end
  return nil, "quic_no_sni_in_crypto", {
    quic_parser_path = "session"
  }
end
local quic_flow_key
quic_flow_key = function(src_ip, dst_ip, src_port, dst_port)
  local a = string.format("%s|%d", src_ip or "unknown", src_port or 0)
  local b = string.format("%s|%d", dst_ip or "unknown", dst_port or 0)
  if a <= b then
    return tostring(a) .. "|" .. tostring(b)
  else
    return tostring(b) .. "|" .. tostring(a)
  end
end
local format_mac
format_mac = function(mac_raw)
  if not (mac_raw and #mac_raw == 6) then
    return "unknown"
  end
  local b1 = mac_raw:byte(1)
  local b2 = mac_raw:byte(2)
  local b3 = mac_raw:byte(3)
  local b4 = mac_raw:byte(4)
  local b5 = mac_raw:byte(5)
  local b6 = mac_raw:byte(6)
  return string.format("%02x:%02x:%02x:%02x:%02x:%02x", b1, b2, b3, b4, b5, b6)
end
local format_ip
format_ip = function(version, ip_raw)
  if not (ip_raw) then
    return "unknown"
  end
  if version == 4 then
    local b1 = ip_raw:byte(1)
    local b2 = ip_raw:byte(2)
    local b3 = ip_raw:byte(3)
    local b4 = ip_raw:byte(4)
    if not (b1 and b2 and b3 and b4) then
      return "unknown"
    end
    return string.format("%d.%d.%d.%d", b1, b2, b3, b4)
  elseif version == 6 then
    return ipparse_ip.ip2s(ip_raw)
  else
    return "unknown"
  end
end
local tsv_field
tsv_field = function(v)
  local s
  if v ~= nil then
    s = tostring(v)
  else
    s = ""
  end
  if #s == 0 then
    return "-"
  else
    return s
  end
end
local write_sni_event
write_sni_event = function(decision, fields)
  if not (events_wfd) then
    return 
  end
  local line = table.concat({
    tostring(os.time()),
    tsv_field(decision),
    tsv_field(fields.sni),
    tsv_field(fields.mac_src),
    tsv_field(fields.src_ip),
    tsv_field(fields.dst_ip),
    tsv_field(fields.vlan),
    tsv_field(fields.user),
    tsv_field(fields.af),
    tsv_field(fields.reason),
    tsv_field(fields.rule)
  }, "\t") .. "\n"
  return libc.write(events_wfd, line, #line)
end
local normalize_sni
normalize_sni = function(sni)
  if not (sni and #sni > 0) then
    return nil
  end
  return sni:lower():gsub("%.+$", "")
end
local protocol_in_scope
protocol_in_scope = function(policy, l4_proto)
  if not (policy) then
    return false
  end
  local p = policy.protocols or "both"
  if p == "both" then
    return true
  end
  if p == "tcp-only" then
    return l4_proto == "tcp"
  end
  if p == "quic-only" then
    return l4_proto == "udp"
  end
  return false
end
local is_mail_ssl_port
is_mail_ssl_port = function(port)
  if port == 465 then
    return true
  end
  if port == 587 then
    return true
  end
  if port == 993 then
    return true
  end
  if port == 995 then
    return true
  end
  return false
end
local is_ipv6
is_ipv6 = function(ip)
  return ip and ip:find(":", 1, true)
end
local safe_filter_decide
safe_filter_decide = function(req)
  if not (filter and filter.decide_meta) then
    return nil, "filter_unavailable", nil
  end
  local ok, meta = pcall(filter.decide_meta, req)
  if not (ok) then
    return nil, "filter_decide_exception", nil
  end
  return meta.verdict, meta.reason, meta.rule_id
end
local ensure_nft_modules
ensure_nft_modules = function()
  if not (cmd_for) then
    local ok_cmd, nft_queue = pcall(require, "nft_queue")
    if not (ok_cmd and nft_queue and nft_queue.cmd_for) then
      return false, "nft_queue_require_failed"
    end
    cmd_for = nft_queue.cmd_for
  end
  if not (run_cmd) then
    local ok_nft, nft_mod = pcall(require, "nft")
    if not (ok_nft and nft_mod and nft_mod.run_cmd) then
      return false, "nft_require_failed"
    end
    run_cmd = nft_mod.run_cmd
  end
  return true, nil
end
local reset_nft_modules
reset_nft_modules = function()
  cmd_for = nil
  run_cmd = nil
end
local apply_nft_allow
apply_nft_allow = function(src_ip, dst_ip, mac, policy, rule_id)
  local ok_mods, mod_err = ensure_nft_modules()
  if not (ok_mods) then
    return false, mod_err
  end
  if not (src_ip and dst_ip and src_ip ~= "unknown" and dst_ip ~= "unknown") then
    return false, "invalid_ip_pair"
  end
  if is_ipv6(src_ip) ~= is_ipv6(dst_ip) then
    return false, "family_mismatch"
  end
  local ip_kind
  if is_ipv6(dst_ip) then
    ip_kind = "ip6"
  else
    ip_kind = "ip4"
  end
  local mac_kind
  if is_ipv6(dst_ip) then
    mac_kind = "mac6"
  else
    mac_kind = "mac4"
  end
  local cmds = { }
  local ip_cmd = cmd_for(ip_kind, src_ip, dst_ip, rule_id, SNI_TIMEOUT)
  if ip_cmd then
    cmds[#cmds + 1] = ip_cmd
  else
    return false, "nft_cmd_build_failed"
  end
  if mac and mac ~= "unknown" and mac ~= "00:00:00:00:00:00" then
    local mac_cmd = cmd_for(mac_kind, mac, dst_ip, rule_id, SNI_TIMEOUT)
    if mac_cmd then
      cmds[#cmds + 1] = mac_cmd
    end
  end
  local ok, err = run_cmd(table.concat(cmds, "\n"), {
    quiet = true
  })
  if ok then
    return true
  end
  if policy and policy.nft_failure_policy == "fail-closed" then
    return false, err or "nft_cmd_failed"
  end
  return true, "nft_failed_fail_open"
end
local handle_sni_packet
handle_sni_packet = function(qh_ptr, nfad, pkt_id)
  log_debug(function()
    return {
      action = "callback",
      pkt_id = pkt_id
    }
  end)
  local l2 = get_l2(nfad)
  if not (l2) then
    log_debug(function()
      return {
        action = "no_l2",
        pkt_id = pkt_id
      }
    end)
    return NF_ACCEPT
  end
  local payload_ptr = ffi.new("unsigned char*[1]")
  local payload_len = libnfq.nfq_get_payload(nfad, payload_ptr)
  if payload_len <= 0 then
    log_debug(function()
      return {
        action = "no_payload",
        pkt_id = pkt_id
      }
    end)
    return NF_ACCEPT
  end
  local raw = ffi.string(payload_ptr[0], payload_len)
  local ip, err = ipparse_ip.parse(raw, 1)
  if not (ip) then
    log_debug(function()
      return {
        action = "ip_parse_failed",
        pkt_id = pkt_id
      }
    end)
    return NF_ACCEPT
  end
  local protocol_name = nil
  local l4_proto = nil
  local sni = nil
  local src_port = nil
  local dst_port = nil
  local tls_reason = nil
  local tls_meta = nil
  if ip.protocol == 6 then
    l4_proto = "tcp"
    local success, tcp = pcall(function()
      return ipparse_tcp.parse(raw, ip.data_off)
    end)
    if not (success and tcp) then
      log_debug(function()
        return {
          action = "tcp_parse_failed",
          pkt_id = pkt_id
        }
      end)
      return NF_ACCEPT
    end
    if not (tcp.data_off and tcp.data_off >= 1) then
      log_debug(function()
        return {
          action = "tcp_data_off_invalid",
          pkt_id = pkt_id
        }
      end)
      return NF_ACCEPT
    end
    src_port = tcp.spt
    dst_port = tcp.dpt
    if is_mail_ssl_port(dst_port) then
      local _exp_0 = dst_port
      if 465 == _exp_0 then
        protocol_name = "smtps"
      elseif 587 == _exp_0 then
        protocol_name = "smtp_starttls"
      elseif 993 == _exp_0 then
        protocol_name = "imaps"
      elseif 995 == _exp_0 then
        protocol_name = "pop3s"
      else
        protocol_name = "mail_ssl"
      end
    else
      protocol_name = "https"
    end
    if tcp.data_off > #raw then
      log_debug(function()
        return {
          action = "tcp_no_payload",
          pkt_id = pkt_id
        }
      end)
      return NF_ACCEPT
    end
    local tls_payload = raw:sub(tcp.data_off)
    if not (tls_payload and #tls_payload > 0) then
      log_debug(function()
        return {
          action = "tcp_no_payload",
          pkt_id = pkt_id
        }
      end)
      return NF_ACCEPT
    end
    if not (tls_payload:byte(1) == 0x16) then
      log_debug(function()
        return {
          action = "tcp_not_tls_handshake",
          pkt_id = pkt_id,
          tls_record_type = string.format("0x%02x", tls_payload:byte(1))
        }
      end)
      return NF_ACCEPT
    end
    sni, tls_reason, tls_meta = extract_sni_from_tls(tls_payload, {
      pkt_id = pkt_id
    })
  elseif ip.protocol == 17 then
    l4_proto = "udp"
    local success, udp = pcall(function()
      return ipparse_udp.parse(raw, ip.data_off)
    end)
    if not (success and udp) then
      log_debug(function()
        return {
          action = "udp_parse_failed",
          pkt_id = pkt_id
        }
      end)
      return NF_ACCEPT
    end
    src_port = udp.spt
    dst_port = udp.dpt
    protocol_name = "quic"
    if udp.data_off <= #raw then
      local quic_payload = raw:sub(udp.data_off)
      local src_ip = format_ip(ip.version, ip.src)
      local dst_ip = format_ip(ip.version, ip.dst)
      local quic_session_key = quic_flow_key(src_ip, dst_ip, src_port, dst_port)
      sni, tls_reason, tls_meta = extract_sni_from_quic(quic_payload, quic_session_key)
    end
  end
  local mac_str = format_mac(l2.mac_raw)
  local ip_src_str = format_ip(ip.version, ip.src)
  local ip_dst_str = format_ip(ip.version, ip.dst)
  local af
  if ip.version == 6 then
    af = "ipv6"
  else
    af = "ipv4"
  end
  local strict_mode = sni_policy and sni_policy.mode == "strict-443"
  local in_scope = protocol_in_scope(sni_policy, l4_proto)
  local mail_port = is_mail_ssl_port(dst_port)
  if not (sni) then
    if protocol_name == "quic" and tls_reason and (tls_reason:match("^quic_session_init_failed") or tls_reason:match("^quic_push_failed")) then
      log_warn(function()
        return {
          action = "quic_parse_failed",
          pkt_id = pkt_id,
          reason = tls_reason,
          quic_parser_path = tls_meta and tls_meta.quic_parser_path
        }
      end)
    end
    if strict_mode and in_scope and not mail_port then
      log_block(function()
        return {
          action = "sni_verdict_block_no_sni",
          pkt_id = pkt_id,
          protocol = protocol_name,
          l4_proto = l4_proto,
          ip_src = ip_src_str,
          ip_dst = ip_dst_str,
          port_src = src_port,
          port_dst = dst_port,
          reason = tls_reason or "no_sni"
        }
      end)
      write_sni_event("block", {
        sni = nil,
        mac_src = mac_str,
        src_ip = ip_src_str,
        dst_ip = ip_dst_str,
        vlan = l2.vlan,
        user = nil,
        af = af,
        reason = tls_reason or "no_sni",
        rule = "strict-443/no_sni"
      })
      return NF_DROP
    end
    if mail_port and strict_mode and in_scope then
      log_warn(function()
        return {
          action = "sni_verdict_warn_no_sni_mail",
          pkt_id = pkt_id,
          protocol = protocol_name,
          l4_proto = l4_proto,
          ip_src = ip_src_str,
          ip_dst = ip_dst_str,
          port_src = src_port,
          port_dst = dst_port,
          reason = tls_reason or "no_sni",
          tls_version = tls_meta and tls_meta.tls_version,
          tls_record_version = tls_meta and tls_meta.tls_record_version,
          tls_client_hello_version = tls_meta and tls_meta.tls_client_hello_version,
          tls_supported_version = tls_meta and tls_meta.tls_supported_version,
          tls_parser_path = tls_meta and tls_meta.tls_parser_path
        }
      end)
      write_sni_event("warn", {
        sni = nil,
        mac_src = mac_str,
        src_ip = ip_src_str,
        dst_ip = ip_dst_str,
        vlan = l2.vlan,
        user = nil,
        af = af,
        reason = tls_reason or "no_sni",
        rule = "mail_ssl/no_sni"
      })
      return NF_ACCEPT
    end
    log_debug(function()
      return {
        action = "sni_verdict_skip_no_sni",
        pkt_id = pkt_id,
        protocol = protocol_name,
        l4_proto = l4_proto,
        reason = tls_reason,
        tls_version = tls_meta and tls_meta.tls_version,
        tls_record_version = tls_meta and tls_meta.tls_record_version,
        tls_client_hello_version = tls_meta and tls_meta.tls_client_hello_version,
        tls_supported_version = tls_meta and tls_meta.tls_supported_version,
        tls_parser_path = tls_meta and tls_meta.tls_parser_path,
        quic_parser_path = tls_meta and tls_meta.quic_parser_path
      }
    end)
    return NF_ACCEPT
  end
  local sni_norm = normalize_sni(sni)
  log_info(function()
    return {
      action = "sni_captured",
      protocol = protocol_name,
      l4_proto = l4_proto,
      sni = sni_norm or sni,
      mac_src = mac_str,
      ip_src = ip_src_str,
      ip_dst = ip_dst_str,
      port_src = src_port,
      port_dst = dst_port,
      tls_version = tls_meta and tls_meta.tls_version,
      tls_record_version = tls_meta and tls_meta.tls_record_version,
      tls_client_hello_version = tls_meta and tls_meta.tls_client_hello_version,
      tls_supported_version = tls_meta and tls_meta.tls_supported_version,
      tls_parser_path = tls_meta and tls_meta.tls_parser_path,
      quic_parser_path = tls_meta and tls_meta.quic_parser_path
    }
  end)
  local req = {
    domain = sni_norm or sni,
    src_ip = ip_src_str,
    mac = mac_str,
    vlan = l2.vlan,
    ts = os.time(),
    user = user_for_mac(mac_str, ip_src_str, auth_sessions_file)
  }
  local allowed, decide_reason, decide_rule = safe_filter_decide(req)
  if not in_scope then
    log_debug(function()
      return {
        action = "sni_verdict_skip_protocol",
        pkt_id = pkt_id,
        protocol = protocol_name,
        l4_proto = l4_proto,
        sni = sni_norm or sni,
        policy_protocols = sni_policy and sni_policy.protocols or "both"
      }
    end)
    return NF_ACCEPT
  end
  if allowed == nil then
    log_warn(function()
      return {
        action = "sni_verdict_skip_filter_error",
        pkt_id = pkt_id,
        protocol = protocol_name,
        l4_proto = l4_proto,
        sni = sni_norm or sni,
        reason = decide_reason or "filter_error"
      }
    end)
    return NF_ACCEPT
  end
  if allowed == true then
    local ok_nft, nft_reason = apply_nft_allow(ip_src_str, ip_dst_str, mac_str, sni_policy, decide_rule)
    if not (ok_nft) then
      log_block(function()
        return {
          action = "sni_verdict_nft_failed",
          pkt_id = pkt_id,
          protocol = protocol_name,
          l4_proto = l4_proto,
          sni = sni_norm or sni,
          ip_src = ip_src_str,
          ip_dst = ip_dst_str,
          mac_src = mac_str,
          reason = nft_reason,
          nft_failure_policy = sni_policy and sni_policy.nft_failure_policy or "fail-closed"
        }
      end)
      write_sni_event("block", {
        sni = sni_norm or sni,
        mac_src = mac_str,
        src_ip = ip_src_str,
        dst_ip = ip_dst_str,
        vlan = l2.vlan,
        user = nil,
        af = af,
        reason = nft_reason,
        rule = decide_rule or "nft_insert_failed"
      })
      if (sni_policy and sni_policy.nft_failure_policy or "fail-closed") == "fail-closed" then
        return NF_DROP
      end
      return NF_ACCEPT
    end
    log_allow(function()
      return {
        action = "sni_verdict_allow",
        protocol = protocol_name,
        l4_proto = l4_proto,
        sni = sni_norm or sni,
        ip_src = ip_src_str,
        ip_dst = ip_dst_str,
        mac_src = mac_str,
        port_src = src_port,
        port_dst = dst_port,
        filter_reason = decide_reason,
        rule = decide_rule,
        nft_outcome = nft_reason or "ok",
        tls_version = tls_meta and tls_meta.tls_version,
        tls_record_version = tls_meta and tls_meta.tls_record_version,
        tls_client_hello_version = tls_meta and tls_meta.tls_client_hello_version,
        tls_supported_version = tls_meta and tls_meta.tls_supported_version,
        tls_parser_path = tls_meta and tls_meta.tls_parser_path,
        quic_parser_path = tls_meta and tls_meta.quic_parser_path
      }
    end)
    write_sni_event("allow", {
      sni = sni_norm or sni,
      mac_src = mac_str,
      src_ip = ip_src_str,
      dst_ip = ip_dst_str,
      vlan = l2.vlan,
      user = nil,
      af = af,
      reason = decide_reason,
      rule = decide_rule
    })
    return NF_ACCEPT
  end
  if allowed == "dnsonly" then
    if strict_mode then
      log_block(function()
        return {
          action = "sni_verdict_block_dnsonly",
          pkt_id = pkt_id,
          protocol = protocol_name,
          l4_proto = l4_proto,
          sni = sni_norm or sni,
          ip_src = ip_src_str,
          ip_dst = ip_dst_str,
          mac_src = mac_str,
          reason = decide_reason or "dnsonly",
          rule = decide_rule
        }
      end)
      write_sni_event("block", {
        sni = sni_norm or sni,
        mac_src = mac_str,
        src_ip = ip_src_str,
        dst_ip = ip_dst_str,
        vlan = l2.vlan,
        user = nil,
        af = af,
        reason = decide_reason or "dnsonly",
        rule = decide_rule or "dnsonly"
      })
      return NF_DROP
    end
    log_debug(function()
      return {
        action = "sni_verdict_skip_dnsonly",
        pkt_id = pkt_id,
        protocol = protocol_name,
        l4_proto = l4_proto,
        sni = sni_norm or sni,
        reason = decide_reason or "dnsonly",
        rule = decide_rule
      }
    end)
    return NF_ACCEPT
  end
  if strict_mode then
    log_block(function()
      return {
        action = "sni_verdict_block",
        pkt_id = pkt_id,
        protocol = protocol_name,
        l4_proto = l4_proto,
        sni = sni_norm or sni,
        ip_src = ip_src_str,
        ip_dst = ip_dst_str,
        mac_src = mac_str,
        reason = decide_reason or "denied",
        rule = decide_rule
      }
    end)
    write_sni_event("block", {
      sni = sni_norm or sni,
      mac_src = mac_str,
      src_ip = ip_src_str,
      dst_ip = ip_dst_str,
      vlan = l2.vlan,
      user = nil,
      af = af,
      reason = decide_reason or "denied",
      rule = decide_rule
    })
    return NF_DROP
  end
  log_debug(function()
    return {
      action = "sni_verdict_skip",
      pkt_id = pkt_id,
      protocol = protocol_name,
      l4_proto = l4_proto,
      sni = sni_norm or sni,
      reason = decide_reason or "denied",
      rule = decide_rule
    }
  end)
  return NF_ACCEPT
end
local run
run = function(queue_num, ev_wfd, filter_data)
  if ev_wfd == nil then
    ev_wfd = nil
  end
  if filter_data == nil then
    filter_data = nil
  end
  set_action_prefix("sni_")
  events_wfd = ev_wfd
  local ok_filter, filter_or_err = pcall(require, "filter")
  if ok_filter and filter_or_err then
    filter = filter_or_err
    if filter_data then
      filter.rules = filter_data.rules
      filter.auth_cfg_cache = filter_data.auth_cfg_cache
      filter.decision_cfg = filter_data.decision_cfg
    end
    local auth_cfg
    if filter.get_auth_cfg then
      auth_cfg = filter.get_auth_cfg()
    else
      auth_cfg = { }
    end
    local auth_sessions_file = auth_cfg.sessions_file or auth_sessions_file
    sni_policy = auth_cfg and auth_cfg.sni_verdict or { }
  else
    filter = nil
    sni_policy = { }
    log_warn(function()
      return {
        action = "filter_require_failed",
        err = tostring(filter_or_err)
      }
    end)
  end
  if sni_policy.enabled == nil then
    sni_policy.enabled = true
  else
    sni_policy.enabled = not not sni_policy.enabled
  end
  sni_policy.mode = sni_policy.mode or "strict-443"
  sni_policy.protocols = sni_policy.protocols or "both"
  sni_policy.nft_failure_policy = sni_policy.nft_failure_policy or "fail-closed"
  log_info(function()
    return {
      action = "starting",
      queue = queue_num
    }
  end)
  if not (sni_policy.enabled) then
    log_info(function()
      return {
        action = "disabled",
        queue = queue_num
      }
    end)
    return run_queue(tonumber(queue_num), function(qh_ptr, nfad, pkt_id)
      return NF_ACCEPT
    end)
  end
  log_info(function()
    return {
      action = "policy_loaded",
      queue = queue_num,
      mode = sni_policy.mode,
      protocols = sni_policy.protocols,
      reset_nft_modules = reset_nft_modules,
      nft_failure_policy = sni_policy.nft_failure_policy
    }
  end)
  return run_queue(tonumber(queue_num), handle_sni_packet)
end
return {
  run = run,
  normalize_sni = normalize_sni,
  protocol_in_scope = protocol_in_scope,
  apply_nft_allow = apply_nft_allow,
  reset_nft_modules = reset_nft_modules
}
