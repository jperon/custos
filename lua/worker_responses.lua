local ffi, libc, libnfq
do
  local _obj_0 = require("ffi_defs")
  ffi, libc, libnfq = _obj_0.ffi, _obj_0.libc, _obj_0.libnfq
end
local config = require("config")
local runtime_cfg = config.runtime or { }
local ipc_cfg = config.ipc or { }
local match_retry_cfg = ipc_cfg.match_retry or { }
local dns_cfg = config.dns or { }
local ttl_cfg = dns_cfg.ttl_grace or { }
local auth_cfg = config.auth or { }
local clients_cfg = config.clients or { }
local user_for_mac
user_for_mac = require("auth.sessions").user_for_mac
local packet = require("nfq/packet")
local QTYPE, parse_answers, extract_dns_payload, replace_dns_payload, purge_tcp_buffers, cleanup
QTYPE, parse_answers, extract_dns_payload, replace_dns_payload, purge_tcp_buffers, cleanup = packet.QTYPE, packet.parse_answers, packet.extract_dns_payload, packet.replace_dns_payload, packet.purge_tcp_buffers, packet.cleanup
local get_l2
get_l2 = require("nfq/ethernet").get_l2
local drain_pipe, is_pending, get_pending_entry, consume
do
  local _obj_0 = require("ipc")
  drain_pipe, is_pending, get_pending_entry, consume = _obj_0.drain_pipe, _obj_0.is_pending, _obj_0.get_pending_entry, _obj_0.consume
end
local add_ip4, add_ip6, add_mac4, add_mac6, get_last_seq, wait_ack
do
  local _obj_0 = require("nft_queue")
  add_ip4, add_ip6, add_mac4, add_mac6, get_last_seq, wait_ack = _obj_0.add_ip4, _obj_0.add_ip6, _obj_0.add_mac4, _obj_0.add_mac6, _obj_0.get_last_seq, _obj_0.wait_ack
end
local run_queue, NF_ACCEPT, NF_DROP
do
  local _obj_0 = require("nfq_loop")
  run_queue, NF_ACCEPT, NF_DROP = _obj_0.run_queue, _obj_0.NF_ACCEPT, _obj_0.NF_DROP
end
local log_info, log_warn, log_debug, now, set_action_prefix
do
  local _obj_0 = require("log")
  log_info, log_warn, log_debug, now, set_action_prefix = _obj_0.log_info, _obj_0.log_warn, _obj_0.log_debug, _obj_0.now, _obj_0.set_action_prefix
end
local build_blocked_response, add_ede_modified, strip_https_rr, clear_ad_bit
do
  local _obj_0 = require("dns_ede")
  build_blocked_response, add_ede_modified, strip_https_rr, clear_ad_bit = _obj_0.build_blocked_response, _obj_0.add_ede_modified, _obj_0.strip_https_rr, _obj_0.clear_ad_bit
end
local bit = require("bit")
local concat, insert, remove
do
  local _obj_0 = table
  concat, insert, remove = _obj_0.concat, _obj_0.insert, _obj_0.remove
end
local IPC_RETRY_ENABLED
if match_retry_cfg.enabled == nil then
  IPC_RETRY_ENABLED = true
else
  IPC_RETRY_ENABLED = match_retry_cfg.enabled
end
local IPC_RETRY_COUNT = match_retry_cfg.count or 5
local IPC_RETRY_SLEEP_MS = match_retry_cfg.sleep_ms or 20
local MAC_ZERO = "00:00:00:00:00:00"
local mac_valid
mac_valid = function(mac)
  return mac ~= "unknown" and mac ~= MAC_ZERO
end
local mac_clients = { }
local ip_to_mac = { }
local pipe_rfd = nil
local sleep_req = ffi.new("timespec_t[1]")
local CLOCK_MONOTONIC = 1
local _benchmark_ts = ffi.new("timespec_t[1]")
local current_benchmark_ms
current_benchmark_ms = function()
  libc.clock_gettime(CLOCK_MONOTONIC, _benchmark_ts)
  return tonumber(_benchmark_ts[0].tv_sec) * 1000 + math.floor(tonumber(_benchmark_ts[0].tv_nsec) / 1000000)
end
local update_mac_clients = nil
local drain_ts = 0
local drain_on_msg
drain_on_msg = function(msg)
  return update_mac_clients(msg, drain_ts)
end
local sleep_ms
sleep_ms = function(ms)
  if not (ms and ms > 0) then
    return 
  end
  sleep_req[0].tv_sec = math.floor(ms / 1000)
  sleep_req[0].tv_nsec = (ms % 1000) * 1000000
  return libc.nanosleep(sleep_req, nil)
end
local retry_pending_match
retry_pending_match = function(txid, client_ip, client_port, resolver_ip)
  if not (IPC_RETRY_ENABLED) then
    return nil, 0, 0
  end
  local tries = IPC_RETRY_COUNT or 0
  local wait_ms = IPC_RETRY_SLEEP_MS or 0
  if tries <= 0 then
    return nil, 0, 0
  end
  local total_wait_ms = 0
  for i = 1, tries do
    sleep_ms(wait_ms)
    total_wait_ms = total_wait_ms + wait_ms
    local ts = now()
    drain_ts = ts
    drain_pipe(pipe_rfd, now, drain_on_msg)
    local entry = get_pending_entry(txid, client_ip, client_port, resolver_ip, now)
    if entry then
      return entry, i, total_wait_ms
    end
  end
  return nil, tries, total_wait_ms
end
update_mac_clients = function(msg, ts)
  local mac = msg.mac_str
  if mac == MAC_ZERO then
    return 
  end
  local entry = mac_clients[mac] or { }
  entry.last_seen = ts
  if msg.ipv4 then
    if not (entry.ipv4 == msg.ip_str) then
      if entry.ipv4 then
        ip_to_mac[entry.ipv4] = nil
      end
      entry.ipv4 = msg.ip_str
      ip_to_mac[msg.ip_str] = mac
    end
  else
    if not (entry.ipv6 == msg.ip_str) then
      if entry.ipv6 then
        ip_to_mac[entry.ipv6] = nil
      end
      entry.ipv6 = msg.ip_str
      ip_to_mac[msg.ip_str] = mac
    end
  end
  mac_clients[mac] = entry
end
local purge_mac_clients
purge_mac_clients = function(ts)
  for mac, entry in pairs(mac_clients) do
    if ts - entry.last_seen > (clients_cfg.expiry or 300) then
      if entry.ipv4 then
        ip_to_mac[entry.ipv4] = nil
      end
      if entry.ipv6 then
        ip_to_mac[entry.ipv6] = nil
      end
      entry.ips = nil
      mac_clients[mac] = nil
      log_info({
        action = "client_expired",
        mac = mac
      })
    end
  end
end
local resolve_client_family
resolve_client_family = function(ip_str, want)
  local mac = ip_to_mac[ip_str]
  if mac then
    local entry = mac_clients[mac]
    local result = entry and entry[want]
    if result then
      return result
    end
  end
  return nil
end
local clamp
clamp = function(value, min_v, max_v)
  if value < min_v then
    return min_v
  end
  if value > max_v then
    return max_v
  end
  return value
end
local rr_timeout
rr_timeout = function(ttl)
  local grace = math.max(0, math.floor(tonumber(ttl_cfg.grace) or 600))
  local min_t = math.max(1, math.floor(tonumber(ttl_cfg.min) or 60))
  local max_t = math.max(min_t, math.floor(tonumber(ttl_cfg.max) or 2592000))
  local rr_ttl = tonumber(ttl) or 0
  rr_ttl = math.floor(rr_ttl)
  if rr_ttl < 0 then
    rr_ttl = 0
  end
  local effective = clamp(rr_ttl + grace, min_t, max_t)
  return tostring(effective) .. "s", effective
end
local patch_modified_dns
patch_modified_dns = function(dns_raw, reason)
  local new_dns = strip_https_rr(dns_raw) or dns_raw
  local payload_modified = new_dns ~= dns_raw
  if payload_modified then
    new_dns = clear_ad_bit(new_dns)
    new_dns = add_ede_modified(new_dns, reason) or new_dns
  end
  return new_dns, payload_modified
end
local handle_response
handle_response = function(qh_ptr, nfad, pkt_id)
  local ts = now()
  drain_ts = ts
  drain_pipe(pipe_rfd, now, drain_on_msg)
  local payload_ptr = ffi.new("unsigned char*[1]")
  local payload_len = libnfq.nfq_get_payload(nfad, payload_ptr)
  if payload_len <= 0 then
    return NF_DROP
  end
  local raw = ffi.string(payload_ptr[0], payload_len)
  local l2 = get_l2(nfad)
  local pkt, parse_status = packet.parse_packet(raw)
  if not (pkt) then
    if parse_status == "buffering" then
      return NF_DROP
    end
    return NF_ACCEPT
  end
  if math.random(1000) == 1 then
    purge_tcp_buffers()
    purge_mac_clients(ts)
  end
  if not (pkt.dns.is_response) then
    return NF_ACCEPT
  end
  local client_port = pkt.l4.dst_port
  local txid = pkt.dns.txid
  local client_ip = pkt.ip.dst_ip
  local resolver_ip = pkt.ip.src_ip
  local client_mac = ip_to_mac[client_ip] or "unknown"
  local user = user_for_mac(client_mac, client_ip, auth_cfg.sessions_file or "/tmp/sessions.lua")
  local entry = get_pending_entry(txid, pkt.ip.dst_ip, client_port, resolver_ip, now)
  if not (entry) then
    local retry_attempts = 0
    local retry_wait_ms = 0
    entry, retry_attempts, retry_wait_ms = retry_pending_match(txid, pkt.ip.dst_ip, client_port, resolver_ip)
    if entry then
      log_info({
        action = "response_matched_after_retry",
        src_ip = pkt.ip.src_ip,
        dst_ip = pkt.ip.dst_ip,
        txid = string.format("0x%04x", txid),
        retry_attempts = retry_attempts,
        retry_wait_ms = retry_wait_ms,
        user = user
      })
    else
      log_debug({
        action = (function()
          if retry_attempts > 0 then
            return "response_no_matching_question_after_retry"
          else
            return "response_no_matching_question"
          end
        end)(),
        src_ip = pkt.ip.src_ip,
        dst_ip = pkt.ip.dst_ip,
        vlan = l2.vlan,
        txid = string.format("0x%04x", txid),
        rcode = pkt.dns.rcode,
        client_mac = client_mac,
        retry_attempts = retry_attempts,
        retry_wait_ms = retry_wait_ms,
        user = user
      })
      return NF_DROP
    end
  end
  consume(txid, pkt.ip.dst_ip, client_port, resolver_ip)
  if runtime_cfg.benchmark and entry and entry.benchmark_ms then
    local delta_ms = current_benchmark_ms() - entry.benchmark_ms
    if delta_ms >= 0 then
      log_info({
        action = "dns_benchmark",
        txid = string.format("0x%04x", txid),
        src_ip = pkt.ip.src_ip,
        dst_ip = pkt.ip.dst_ip,
        delta_ms = delta_ms,
        refused = entry.refused,
        dnsonly = entry.dnsonly,
        user = user
      })
    end
  end
  local refused = entry and entry.refused or false
  local dnsonly = entry and entry.dnsonly or false
  local nft_rule_id = (entry and entry.rule_id and #entry.rule_id > 0) and entry.rule_id or "unknown_rule"
  local ack_corr = string.format("%04x:%s:%d:%s", txid, pkt.ip.dst_ip, client_port, resolver_ip)
  if refused then
    local dns_raw = extract_dns_payload(raw, pkt)
    local refused_dns = build_blocked_response(pkt.dns, dns_raw, entry.reason)
    if not (refused_dns) then
      return NF_DROP
    end
    refused_dns = strip_https_rr(refused_dns) or refused_dns
    local patched = replace_dns_payload(raw, pkt, refused_dns)
    if not (patched) then
      return NF_DROP
    end
    local qnames = table.concat((function()
      local _accum_0 = { }
      local _len_0 = 1
      local _list_0 = pkt.questions
      for _index_0 = 1, #_list_0 do
        local q = _list_0[_index_0]
        _accum_0[_len_0] = q.qname
        _len_0 = _len_0 + 1
      end
      return _accum_0
    end)(), ",")
    log_debug({
      action = "response_refused",
      src_ip = pkt.ip.src_ip,
      dst_ip = pkt.ip.dst_ip,
      vlan = l2.vlan,
      txid = string.format("0x%04x", txid),
      qnames = qnames,
      client_mac = client_mac,
      user = user
    })
    local patched_ptr = ffi.cast("const unsigned char*", patched)
    libnfq.nfq_set_verdict(qh_ptr, pkt_id, NF_ACCEPT, #patched, patched_ptr)
    return -1
  end
  local answers = parse_answers(raw, pkt)
  client_ip = pkt.ip.dst_ip
  local client_v4 = nil
  local client_v6 = nil
  local ip_count = 0
  local records_to_add = 0
  local success_any = false
  local no_ipv4_records = { }
  local no_ipv6_records = { }
  for _index_0 = 1, #answers do
    local ans = answers[_index_0]
    if ans.rtype == QTYPE.A then
      client_v4 = client_v4 or (function()
        if pkt.ip.version == 4 then
          return client_ip
        else
          return resolve_client_family(client_ip, "ipv4")
        end
      end)()
      if not (dnsonly) then
        if client_v4 then
          records_to_add = records_to_add + 1
          local rr_timeout_str, _ = rr_timeout(ans.ttl)
          local ok = add_ip4(client_v4, ans.rdata_str, nft_rule_id, rr_timeout_str, ack_corr)
          if ok then
            ip_count = ip_count + 1
          end
          success_any = success_any or ok
        else
          no_ipv4_records[#no_ipv4_records + 1] = ans.rdata_str
        end
        if mac_valid(client_mac) then
          local rr_timeout_str, _ = rr_timeout(ans.ttl)
          local m_ok = add_mac4(client_mac, ans.rdata_str, nft_rule_id, rr_timeout_str, ack_corr)
          success_any = success_any or m_ok
        end
      end
    elseif ans.rtype == QTYPE.AAAA then
      client_v6 = client_v6 or (function()
        if pkt.ip.version == 6 then
          return client_ip
        else
          return resolve_client_family(client_ip, "ipv6")
        end
      end)()
      if not (dnsonly) then
        if client_v6 then
          records_to_add = records_to_add + 1
          local rr_timeout_str, _ = rr_timeout(ans.ttl)
          local ok = add_ip6(client_v6, ans.rdata_str, nft_rule_id, rr_timeout_str, ack_corr)
          if ok then
            ip_count = ip_count + 1
          end
          success_any = success_any or ok
        else
          no_ipv6_records[#no_ipv6_records + 1] = ans.rdata_str
        end
        if mac_valid(client_mac) then
          local rr_timeout_str, _ = rr_timeout(ans.ttl)
          local m_ok = add_mac6(client_mac, ans.rdata_str, nft_rule_id, rr_timeout_str, ack_corr)
          success_any = success_any or m_ok
        end
      end
    end
  end
  if #no_ipv4_records > 0 then
    local log
    if mac_valid(client_mac) then
      log = log_info
    else
      log = log_warn
    end
    log({
      action = "no_ipv4_for_client",
      client = client_ip,
      count = #no_ipv4_records,
      records = table.concat(no_ipv4_records, " "),
      reason = "client_ipv4_unknown",
      mac_fallback = mac_valid(client_mac),
      user = user
    })
  end
  if #no_ipv6_records > 0 then
    local log
    if mac_valid(client_mac) then
      log = log_info
    else
      log = log_warn
    end
    log({
      action = "no_ipv6_for_client",
      client = client_ip,
      count = #no_ipv6_records,
      records = table.concat(no_ipv6_records, " "),
      reason = "client_ipv6_unknown",
      mac_fallback = mac_valid(client_mac),
      user = user
    })
  end
  local dns_raw = extract_dns_payload(raw, pkt)
  local new_dns, payload_modified = patch_modified_dns(dns_raw, entry.reason)
  local patched = nil
  if payload_modified then
    patched = replace_dns_payload(raw, pkt, new_dns)
    if not (patched) then
      return NF_DROP
    end
  end
  local qnames = table.concat((function()
    local _accum_0 = { }
    local _len_0 = 1
    local _list_0 = pkt.questions
    for _index_0 = 1, #_list_0 do
      local q = _list_0[_index_0]
      _accum_0[_len_0] = q.qname
      _len_0 = _len_0 + 1
    end
    return _accum_0
  end)(), ",")
  log_debug({
    action = (function()
      if dnsonly then
        return "response_dnsonly"
      elseif payload_modified then
        return "response_patched"
      else
        return "response_allow"
      end
    end)(),
    src_ip = pkt.ip.src_ip,
    dst_ip = pkt.ip.dst_ip,
    vlan = l2.vlan,
    txid = string.format("0x%04x", txid),
    qnames = qnames,
    answers = ip_count,
    nft_rule_id = nft_rule_id,
    payload_modified = payload_modified,
    rcode = pkt.dns.rcode,
    client_mac = client_mac,
    user = user
  })
  if records_to_add > 0 and not success_any then
    if ((config.nft or { }).add_failure_policy or "fail-closed") == "fail-closed" then
      log_debug({
        action = "nft_add_failed_policy_fail_closed",
        txid = string.format("0x%04x", txid),
        client_ip = client_ip,
        qnames = qnames,
        user = user
      })
      return NF_DROP
    else
      log_warn({
        action = "nft_add_failed_fail_open",
        txid = string.format("0x%04x", txid),
        client_ip = client_ip,
        qnames = qnames,
        user = user
      })
    end
  end
  if not dnsonly and records_to_add > 0 then
    local pending_seq = get_last_seq()
    if pending_seq then
      wait_ack(pending_seq, ack_corr)
    end
  end
  if not (payload_modified) then
    return NF_ACCEPT
  end
  local patched_ptr = ffi.cast("const unsigned char*", patched)
  libnfq.nfq_set_verdict(qh_ptr, pkt_id, NF_ACCEPT, #patched, patched_ptr)
  return -1
end
local run
run = function(queue_num, rfd)
  set_action_prefix("response_")
  if type(rfd) == "table" then
    local nft_q = require("nft_queue")
    if rfd.nft_wfd then
      nft_q.set_wfd(rfd.nft_wfd)
    end
    if rfd.ack_rfd and rfd.worker_idx ~= nil then
      nft_q.set_ack_rfd(rfd.ack_rfd, rfd.worker_idx)
    end
    rfd = rfd.question_response_rfd
  end
  pipe_rfd = rfd
  run_queue(tonumber(queue_num), handle_response)
  return cleanup()
end
return {
  run = run,
  rr_timeout = rr_timeout,
  patch_modified_dns = patch_modified_dns
}
