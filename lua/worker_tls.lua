local ffi, libc, libnfq
do
  local _obj_0 = require("ffi_defs")
  ffi, libc, libnfq = _obj_0.ffi, _obj_0.libc, _obj_0.libnfq
end
local run_queue, NF_ACCEPT, NF_DROP, VERDICT_DONE, set_verdict_marked
do
  local _obj_0 = require("nfq_loop")
  run_queue, NF_ACCEPT, NF_DROP, VERDICT_DONE, set_verdict_marked = _obj_0.run_queue, _obj_0.NF_ACCEPT, _obj_0.NF_DROP, _obj_0.VERDICT_DONE, _obj_0.set_verdict_marked
end
local REJECT_MARK, REJECT_MARK_HEX
do
  local _obj_0 = require("nft_marks")
  REJECT_MARK, REJECT_MARK_HEX = _obj_0.REJECT_MARK, _obj_0.REJECT_MARK_HEX
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
local ipparse_tls = require("ipparse.l7.tls")
local ipparse_tls_handshake = require("ipparse.l7.tls.handshake")
local ipparse_tls_client_hello = require("ipparse.l7.tls.handshake.client_hello")
local ipparse_server_name = require("ipparse.l7.tls.handshake.extension.server_name")
local ipparse_supported_versions = require("ipparse.l7.tls.handshake.extension.supported_versions")
local new_tcp_stream
new_tcp_stream = require("ipparse.l4.tcp_stream").new
local mac2s
mac2s = require("packet_utils").mac2s
local bit = require("bit")
local nft
nft = require("config").nft
local nft_cfg = nft or { }
local SNI_TIMEOUT = nft_cfg.sni_timeout or nft_cfg.ip_timeout or "2m"
local quic_sessions = { }
local quic_sessions_seen = { }
local quic_sessions_count = 0
local QUIC_SESSION_TTL = 30
local QUIC_SESSION_MAX = 4096
local tls_record_complete
tls_record_complete = function(buf)
  if buf:byte(1) ~= 0x16 then
    return true
  end
  if #buf < 5 then
    return false
  end
  local rec_len = buf:byte(4) * 256 + buf:byte(5)
  return #buf >= 5 + rec_len
end
local tcp_state = new_tcp_stream(tls_record_complete)
local TCP_PURGE_EVERY = 512
local tcp_pkt_count = 0
local filter = nil
local sni_policy = nil
local cmd_for = nil
local run_cmd = nil
local events_wfd = nil
local second_opinion_cfg = nil
local validator_mod = nil
local cname_mod = nil
local filter_cfg = nil
local mark_packet_for_reject
mark_packet_for_reject = function(qh_ptr, pkt_id, setter)
  if setter == nil then
    setter = set_verdict_marked
  end
  local ok, rc = pcall(setter, qh_ptr, pkt_id, NF_ACCEPT, REJECT_MARK)
  if ok and rc >= 0 then
    return true, nil
  end
  return false, tostring(rc)
end
local sni_verdict_cache = { }
local sni_verdict_count = 0
local SNI_VERDICT_TTL = 60
local SNI_VERDICT_MAX = 4096
local prune_quic_sessions
prune_quic_sessions = function(now)
  if now == nil then
    now = os.time()
  end
  local removed = 0
  for key, seen in pairs(quic_sessions_seen) do
    if now - seen >= QUIC_SESSION_TTL then
      quic_sessions[key] = nil
      quic_sessions_seen[key] = nil
      removed = removed + 1
    end
  end
  quic_sessions_count = quic_sessions_count - removed
  return removed
end
local reset_quic_sessions
reset_quic_sessions = function()
  for k in pairs(quic_sessions) do
    quic_sessions[k] = nil
  end
  for k in pairs(quic_sessions_seen) do
    quic_sessions_seen[k] = nil
  end
  quic_sessions_count = 0
end
local seed_quic_session
seed_quic_session = function(key, seen)
  if seen == nil then
    seen = os.time()
  end
  if not (quic_sessions[key]) then
    quic_sessions[key] = {
      stub = true
    }
    quic_sessions_count = quic_sessions_count + 1
  end
  quic_sessions_seen[key] = seen
  return quic_sessions_count
end
local quic_session_count
quic_session_count = function()
  return quic_sessions_count
end
local reset_tcp_sessions
reset_tcp_sessions = function()
  tcp_state.reset()
  tcp_pkt_count = 0
end
local feed_tls_segment
feed_tls_segment = function(key, segment, flags, seq)
  tcp_pkt_count = tcp_pkt_count + 1
  if tcp_pkt_count >= TCP_PURGE_EVERY then
    tcp_state.purge()
    tcp_pkt_count = 0
  end
  return tcp_state.feed(key, segment, flags, seq)
end
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
  local mk_meta
  mk_meta = function(path)
    return {
      tls_version = tls_version,
      tls_record_version = tls_record_version,
      tls_client_hello_version = tls_client_hello_version,
      tls_supported_version = tls_supported_version,
      tls_parser_path = path
    }
  end
  local debug_tls
  debug_tls = function(action, extra)
    if extra == nil then
      extra = nil
    end
    local e = mk_meta(nil)
    e.action = action
    e.pkt_id = ctx.pkt_id
    e.tls_len = payload and #payload or 0
    if extra then
      for k, v in pairs(extra) do
        e[k] = v
      end
    end
    return log_debug(function()
      return e
    end)
  end
  local fail
  fail = function(path, reason, extra)
    debug_tls("tls_parse_" .. tostring(reason), extra)
    return nil, reason, mk_meta(path)
  end
  debug_tls("tls_parse_start")
  if not (payload and #payload >= 9) then
    return fail("none", "short_payload")
  end
  local record_type = payload:byte(1)
  if not (record_type == 0x16) then
    return fail("none", "not_handshake_record", {
      tls_record_type = string.format("0x%02x", record_type)
    })
  end
  local hs_type = payload:byte(6)
  if not (hs_type == 0x01) then
    return fail("none", "not_client_hello", {
      hs_type = string.format("0x%02x", hs_type)
    })
  end
  local success, client_hello_parsed = pcall(function()
    return ipparse_tls_client_hello.parse(payload, 10)
  end)
  if success and client_hello_parsed and client_hello_parsed.extensions and #client_hello_parsed.extensions > 0 then
    if client_hello_parsed.version then
      tls_client_hello_version = tls_version_name(client_hello_parsed.version)
      tls_version = tls_client_hello_version or tls_record_version
    end
    local ext_data = client_hello_parsed.extensions
    local i = 1
    while i + 3 <= #ext_data do
      local ext_type = (ext_data:byte(i)) * 256 + ext_data:byte(i + 1)
      local ext_len = (ext_data:byte(i + 2)) * 256 + ext_data:byte(i + 3)
      local ext_payload_offset = i + 4
      if ext_payload_offset + ext_len - 1 > #ext_data then
        break
      end
      if ext_type == 0 then
        local sni_data = ext_data:sub(ext_payload_offset, ext_payload_offset + ext_len - 1)
        local success_sni, sni_list = pcall(function()
          return ipparse_server_name.parse(sni_data, 1)
        end)
        if success_sni and sni_list and sni_list.name then
          debug_tls("tls_parse_strict_sni_found", {
            sni = sni_list.name
          })
          return sni_list.name, nil, mk_meta("strict")
        end
      end
      if ext_type == 0x002b then
        local sv = extract_supported_versions(ext_data:sub(ext_payload_offset, ext_payload_offset + ext_len - 1))
        if sv then
          tls_supported_version = sv
          tls_version = tls_supported_version
        end
      end
      i = ext_payload_offset + ext_len
    end
  end
  local offset = 10
  if not (#payload >= offset + 33) then
    return fail("fallback", "fallback_short_random")
  end
  offset = offset + 34
  local session_id_len = payload:byte(offset)
  if not (session_id_len) then
    return fail("fallback", "fallback_no_session_id_len")
  end
  offset = offset + 1
  if not (#payload >= offset + session_id_len - 1) then
    return fail("fallback", "fallback_short_session_id", {
      session_id_len = session_id_len
    })
  end
  offset = offset + session_id_len
  if not (#payload >= offset + 1) then
    return fail("fallback", "fallback_short_cipher_len")
  end
  local cipher_suites_len = (payload:byte(offset) * 256) + payload:byte(offset + 1)
  offset = offset + 2
  if not (#payload >= offset + cipher_suites_len - 1) then
    return fail("fallback", "fallback_short_cipher_suites", {
      cipher_suites_len = cipher_suites_len
    })
  end
  offset = offset + cipher_suites_len
  if not (#payload >= offset) then
    return fail("fallback", "fallback_short_compression_len")
  end
  local compression_len = payload:byte(offset)
  offset = offset + 1
  if not (#payload >= offset + compression_len - 1) then
    return fail("fallback", "fallback_short_compression", {
      compression_len = compression_len
    })
  end
  offset = offset + compression_len
  if not (#payload >= offset + 1) then
    return fail("fallback", "fallback_short_extensions_len")
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
        return fail("fallback", "fallback_short_sni_ext")
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
        return sni, nil, mk_meta("fallback")
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
  return nil, "no_sni_in_extensions", mk_meta("fallback")
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
  local now = os.time()
  if quic_sessions_count >= QUIC_SESSION_MAX then
    prune_quic_sessions(now)
  end
  local drop_session
  drop_session = function()
    if session_key and quic_sessions[session_key] then
      quic_sessions[session_key] = nil
      quic_sessions_seen[session_key] = nil
      quic_sessions_count = quic_sessions_count - 1
    end
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
      quic_sessions_count = quic_sessions_count + 1
    end
  end
  if session_key then
    quic_sessions_seen[session_key] = now
  end
  local ok_push, push_err = session:push(quic_payload)
  if not (ok_push) then
    drop_session()
    return nil, "quic_push_failed:" .. tostring(push_err), {
      quic_parser_path = "session"
    }
  end
  local sni = session:sni()
  if sni and #sni > 0 then
    drop_session()
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
  return mac2s(mac_raw)
end
local format_ip
format_ip = function(version, ip_raw)
  if not (ip_raw and (version == 4 or version == 6)) then
    return "unknown"
  end
  if version == 4 and #ip_raw < 4 then
    return "unknown"
  end
  return ipparse_ip.ip2s(ip_raw)
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
    return nil, "filter_unavailable"
  end
  local ok, meta = pcall(filter.decide_meta, req)
  if not (ok) then
    return nil, "filter_decide_exception"
  end
  return meta
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
local sni_action_for
sni_action_for = function(meta)
  if not (meta) then
    return "accept"
  end
  local v = meta.verdict
  if v == nil then
    return "accept"
  end
  if v == false then
    return "block"
  end
  if v == "dnsonly" then
    return "dnsonly"
  end
  if meta.redirects_destination then
    return "redirect"
  end
  if meta.allow_modifiers and meta.allow_modifiers.validate then
    return "validate"
  end
  return "allow"
end
local ensure_validator
ensure_validator = function()
  if not (validator_mod) then
    local ok, mod = pcall(require, "doh.validator")
    if not (ok and mod and mod.query_verdict) then
      return false, "validator_require_failed"
    end
    validator_mod = mod
  end
  return true, nil
end
local ensure_cname
ensure_cname = function()
  if not (cname_mod) then
    local ok, mod = pcall(require, "filter.actions.cname")
    if not (ok and mod and mod.resolve_target_rrs) then
      return false, "cname_require_failed"
    end
    cname_mod = mod
  end
  return true, nil
end
local build_validator_query
build_validator_query = function(domain)
  local parts = { }
  local txid = math.random(0, 0xFFFF)
  local hi = math.floor(txid / 256)
  local lo = txid % 256
  parts[#parts + 1] = string.char(hi, lo, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
  for label in domain:gmatch("[^.]+") do
    parts[#parts + 1] = string.char(#label)
    parts[#parts + 1] = label
  end
  parts[#parts + 1] = string.char(0)
  parts[#parts + 1] = string.char(0x00, 0x01, 0x00, 0x01)
  return table.concat(parts)
end
local prune_sni_verdicts
prune_sni_verdicts = function(now)
  if now == nil then
    now = os.time()
  end
  local removed = 0
  for domain, entry in pairs(sni_verdict_cache) do
    if entry.expires_at <= now then
      sni_verdict_cache[domain] = nil
      removed = removed + 1
    end
  end
  sni_verdict_count = sni_verdict_count - removed
  return removed
end
local reset_sni_verdicts
reset_sni_verdicts = function()
  for k in pairs(sni_verdict_cache) do
    sni_verdict_cache[k] = nil
  end
  sni_verdict_count = 0
end
local set_validator_state
set_validator_state = function(state)
  if state == nil then
    state = { }
  end
  if state.validator_mod ~= nil then
    validator_mod = state.validator_mod
  end
  if state.cname_mod ~= nil then
    cname_mod = state.cname_mod
  end
  if state.second_opinion_cfg ~= nil then
    second_opinion_cfg = state.second_opinion_cfg
  end
  if state.filter_cfg ~= nil then
    filter_cfg = state.filter_cfg
  end
end
local validate_sni
validate_sni = function(domain, validate_modifier)
  if not (domain and domain ~= "") then
    return false, nil
  end
  local now = os.time()
  local cached = sni_verdict_cache[domain]
  if cached and cached.expires_at > now then
    return cached.blocked, cached.reason
  end
  local ok_mod, mod_err = ensure_validator()
  if not (ok_mod) then
    return false, mod_err
  end
  local resolvers
  if type(validate_modifier) == "table" then
    resolvers = validate_modifier
  else
    resolvers = second_opinion_cfg and second_opinion_cfg.resolvers
  end
  if not (resolvers and #resolvers > 0) then
    return false, "no_validator_resolvers"
  end
  local budget = (second_opinion_cfg and second_opinion_cfg.budget_ms) or 1000
  local doh_budget = (second_opinion_cfg and second_opinion_cfg.doh_budget_ms) or 3000
  local dns_raw = build_validator_query(domain)
  local ok_q, blocked, reason = pcall(validator_mod.query_verdict, dns_raw, resolvers, budget, doh_budget)
  blocked = ok_q and blocked or false
  reason = ok_q and reason or nil
  local ttl = (second_opinion_cfg and second_opinion_cfg.verdict_ttl_s) or SNI_VERDICT_TTL
  if sni_verdict_count >= SNI_VERDICT_MAX then
    prune_sni_verdicts(now)
  end
  if not (sni_verdict_cache[domain]) then
    sni_verdict_count = sni_verdict_count + 1
  end
  sni_verdict_cache[domain] = {
    blocked = blocked,
    reason = reason,
    expires_at = now + ttl
  }
  return blocked, reason
end
local dst_matches_cname
dst_matches_cname = function(target, ip_dst, version)
  if not (target and target ~= "" and ip_dst and ip_dst ~= "unknown") then
    return false, false
  end
  local ok_mod = ensure_cname()
  if not (ok_mod) then
    return false, false
  end
  local resolver_ip = cname_mod.pick_resolver_ip(filter_cfg, nil)
  local ok_r, rrs = pcall(cname_mod.resolve_target_rrs, filter_cfg, target, resolver_ip)
  if not (ok_r and rrs) then
    return false, false
  end
  local list
  if version == 6 then
    list = rrs.aaaa
  else
    list = rrs.a
  end
  if not (list and #list > 0) then
    return false, true
  end
  for _index_0 = 1, #list do
    local rdata = list[_index_0]
    if ipparse_ip.ip2s(rdata) == ip_dst then
      return true, true
    end
  end
  return false, true
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
    local segment = raw:sub(tcp.data_off)
    local src_ip_k = format_ip(ip.version, ip.src)
    local dst_ip_k = format_ip(ip.version, ip.dst)
    local tcp_key = tostring(src_ip_k) .. "|" .. tostring(src_port) .. "|" .. tostring(dst_ip_k) .. "|" .. tostring(dst_port)
    local tls_payload = feed_tls_segment(tcp_key, segment, tcp.flags, tcp.seq_n)
    if not (tls_payload) then
      log_debug(function()
        return {
          action = "tcp_buffering",
          pkt_id = pkt_id
        }
      end)
      return NF_ACCEPT
    end
    local ok_rec, tls_rec = pcall(function()
      return ipparse_tls.parse(tls_payload, 1)
    end)
    if not (ok_rec and tls_rec and tls_rec.type == ipparse_tls.record_types.handshake) then
      log_debug(function()
        return {
          action = "tcp_not_tls_handshake",
          pkt_id = pkt_id
        }
      end)
      return NF_ACCEPT
    end
    local ok_hs, hs_hdr = pcall(function()
      return ipparse_tls_handshake.parse(tls_payload, tls_rec.data_off)
    end)
    if not (ok_hs and hs_hdr and hs_hdr.type == ipparse_tls_handshake.message_types.client_hello) then
      log_debug(function()
        return {
          action = "tcp_not_client_hello",
          pkt_id = pkt_id
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
  local worker_src
  if l4_proto == "udp" then
    worker_src = "sni-quic"
  else
    worker_src = "sni-tls"
  end
  local sni_event
  sni_event = function(decision, sni_val, reason, rule)
    return write_sni_event(decision, {
      sni = sni_val,
      mac_src = mac_str,
      src_ip = ip_src_str,
      dst_ip = ip_dst_str,
      vlan = l2.vlan,
      user = nil,
      af = af,
      reason = reason,
      rule = rule
    })
  end
  local with_meta
  with_meta = function(e)
    if tls_meta then
      e.tls_version = tls_meta.tls_version
      e.tls_record_version = tls_meta.tls_record_version
      e.tls_client_hello_version = tls_meta.tls_client_hello_version
      e.tls_supported_version = tls_meta.tls_supported_version
      e.tls_parser_path = tls_meta.tls_parser_path
      e.quic_parser_path = tls_meta.quic_parser_path
    end
    return e
  end
  local sni_norm = nil
  local reject_with_worker
  reject_with_worker = function(reason, event_rule)
    if l4_proto == "udp" then
      log_debug(function()
        return {
          action = "sni_quic_drop",
          worker = worker_src,
          pkt_id = pkt_id,
          protocol = protocol_name,
          l4_proto = l4_proto,
          sni = sni_norm or sni,
          ip_src = ip_src_str,
          ip_dst = ip_dst_str,
          mac_src = mac_str,
          reason = reason,
          rule = event_rule
        }
      end)
      return NF_DROP
    end
    local ok_mark, mark_err = mark_packet_for_reject(qh_ptr, pkt_id)
    if not (ok_mark) then
      log_error(function()
        return {
          action = "sni_reject_mark_failed",
          worker = worker_src,
          pkt_id = pkt_id,
          protocol = protocol_name,
          l4_proto = l4_proto,
          sni = sni_norm or sni,
          ip_src = ip_src_str,
          ip_dst = ip_dst_str,
          mac_src = mac_str,
          reason = reason,
          rule = event_rule,
          reject_mark = REJECT_MARK_HEX,
          err = mark_err
        }
      end)
      return NF_DROP
    end
    log_debug(function()
      return {
        action = "sni_reject_marked",
        worker = worker_src,
        pkt_id = pkt_id,
        protocol = protocol_name,
        l4_proto = l4_proto,
        sni = sni_norm or sni,
        ip_src = ip_src_str,
        ip_dst = ip_dst_str,
        mac_src = mac_str,
        reason = reason,
        rule = event_rule,
        reject_mark = REJECT_MARK_HEX
      }
    end)
    return VERDICT_DONE
  end
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
          worker = worker_src,
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
      sni_event("block", nil, tls_reason or "no_sni", "strict-443/no_sni")
      return reject_with_worker(tls_reason or "no_sni", "strict-443/no_sni")
    end
    if mail_port and strict_mode and in_scope then
      log_warn(function()
        return with_meta({
          action = "sni_verdict_warn_no_sni_mail",
          pkt_id = pkt_id,
          protocol = protocol_name,
          l4_proto = l4_proto,
          ip_src = ip_src_str,
          ip_dst = ip_dst_str,
          port_src = src_port,
          port_dst = dst_port,
          reason = tls_reason or "no_sni"
        })
      end)
      sni_event("warn", nil, tls_reason or "no_sni", "mail_ssl/no_sni")
      return NF_ACCEPT
    end
    log_debug(function()
      return with_meta({
        action = "sni_verdict_skip_no_sni",
        pkt_id = pkt_id,
        protocol = protocol_name,
        l4_proto = l4_proto,
        reason = tls_reason
      })
    end)
    return NF_ACCEPT
  end
  sni_norm = normalize_sni(sni)
  log_info(function()
    return with_meta({
      action = "sni_captured",
      protocol = protocol_name,
      l4_proto = l4_proto,
      sni = sni_norm or sni,
      mac_src = mac_str,
      ip_src = ip_src_str,
      ip_dst = ip_dst_str,
      port_src = src_port,
      port_dst = dst_port
    })
  end)
  local req = {
    domain = sni_norm or sni,
    src_ip = ip_src_str,
    mac = mac_str,
    vlan = l2.vlan,
    ts = os.time(),
    user = user_for_mac(mac_str, ip_src_str, auth_sessions_file)
  }
  local meta, decide_err = safe_filter_decide(req)
  local decide_reason = (meta and meta.reason) or decide_err
  local decide_rule = meta and meta.rule_id
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
  local action = sni_action_for(meta)
  if action == "accept" then
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
  local block_or_skip
  block_or_skip = function(action_block, action_skip, reason, event_rule)
    if strict_mode then
      log_block(function()
        return {
          action = action_block,
          worker = worker_src,
          pkt_id = pkt_id,
          protocol = protocol_name,
          l4_proto = l4_proto,
          sni = sni_norm or sni,
          ip_src = ip_src_str,
          ip_dst = ip_dst_str,
          mac_src = mac_str,
          reason = reason,
          rule = decide_rule
        }
      end)
      sni_event("block", sni_norm or sni, reason, event_rule)
      return reject_with_worker(reason, event_rule)
    end
    log_debug(function()
      return {
        action = action_skip,
        pkt_id = pkt_id,
        protocol = protocol_name,
        l4_proto = l4_proto,
        sni = sni_norm or sni,
        reason = reason,
        rule = decide_rule
      }
    end)
    return NF_ACCEPT
  end
  local do_allow
  do_allow = function()
    local ok_nft, nft_reason = apply_nft_allow(ip_src_str, ip_dst_str, mac_str, sni_policy, decide_rule)
    if not (ok_nft) then
      log_block(function()
        return {
          action = "sni_verdict_nft_failed",
          worker = worker_src,
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
      sni_event("block", sni_norm or sni, nft_reason, decide_rule or "nft_insert_failed")
      if (sni_policy and sni_policy.nft_failure_policy or "fail-closed") == "fail-closed" then
        return reject_with_worker(nft_reason, decide_rule or "nft_insert_failed")
      end
      return NF_ACCEPT
    end
    log_allow(function()
      return with_meta({
        action = "sni_verdict_allow",
        worker = worker_src,
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
        nft_outcome = nft_reason or "ok"
      })
    end)
    sni_event("allow", sni_norm or sni, decide_reason, decide_rule)
    return NF_ACCEPT
  end
  local _exp_0 = action
  if "allow" == _exp_0 then
    return do_allow()
  elseif "redirect" == _exp_0 then
    local matched, resolved = dst_matches_cname(meta.cname_target, ip_dst_str, ip.version)
    if matched then
      return do_allow()
    end
    local redirect_reason
    if resolved then
      redirect_reason = "sni_redirect_wrong_ip"
    else
      redirect_reason = "sni_redirect_target_unresolved"
    end
    return block_or_skip("sni_verdict_block_redirect", "sni_verdict_skip_redirect", redirect_reason, "sni_redirect_blocked")
  elseif "validate" == _exp_0 then
    local blocked, vreason = validate_sni((sni_norm or sni), meta.allow_modifiers.validate)
    if not (blocked) then
      return do_allow()
    end
    return block_or_skip("sni_verdict_block_validator", "sni_verdict_skip_validator", vreason or "validator_blocked", "sni_validator_blocked")
  elseif "dnsonly" == _exp_0 then
    return block_or_skip("sni_verdict_block_dnsonly", "sni_verdict_skip_dnsonly", decide_reason or "dnsonly", decide_rule or "dnsonly")
  else
    return block_or_skip("sni_verdict_block", "sni_verdict_skip", decide_reason or "denied", decide_rule)
  end
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
      filter.sni_cfg_cache = filter_data.sni_cfg_cache
      filter.decision_cfg = filter_data.decision_cfg
    end
    local auth_cfg
    if filter.get_auth_cfg then
      auth_cfg = filter.get_auth_cfg()
    else
      auth_cfg = { }
    end
    local auth_sessions_file = auth_cfg.sessions_file or auth_sessions_file
    if filter.get_sni_cfg then
      sni_policy = filter.get_sni_cfg()
    else
      sni_policy = { }
    end
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
  local ok_cfg, full_cfg = pcall(require, "config")
  if ok_cfg and full_cfg then
    filter_cfg = full_cfg
    second_opinion_cfg = full_cfg.second_opinion
  end
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
  reset_nft_modules = reset_nft_modules,
  extract_sni_from_tls = extract_sni_from_tls,
  extract_sni_from_quic = extract_sni_from_quic,
  quic_flow_key = quic_flow_key,
  prune_quic_sessions = prune_quic_sessions,
  reset_quic_sessions = reset_quic_sessions,
  seed_quic_session = seed_quic_session,
  quic_session_count = quic_session_count,
  reset_tcp_sessions = reset_tcp_sessions,
  feed_tls_segment = feed_tls_segment,
  mark_packet_for_reject = mark_packet_for_reject,
  sni_action_for = sni_action_for,
  validate_sni = validate_sni,
  dst_matches_cname = dst_matches_cname,
  build_validator_query = build_validator_query,
  prune_sni_verdicts = prune_sni_verdicts,
  reset_sni_verdicts = reset_sni_verdicts,
  set_validator_state = set_validator_state
}
