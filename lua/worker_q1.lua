local ffi, libc, libnfq
do
  local _obj_0 = require("ffi_defs")
  ffi, libc, libnfq = _obj_0.ffi, _obj_0.libc, _obj_0.libnfq
end
local QUEUE_RESPONSES, DOCKER_MODE, FORCED_TTL, CLIENT_EXPIRY, NEIGH_REFRESH_COOLDOWN, NFT_ADD_RETRY_COUNT, NFT_ADD_BACKOFF_MS, NFT_ADD_FAILURE_POLICY, IPC_MATCH_RETRY_ENABLED, IPC_MATCH_RETRY_COUNT, IPC_MATCH_RETRY_SLEEP_MS
do
  local _obj_0 = require("config")
  QUEUE_RESPONSES, DOCKER_MODE, FORCED_TTL, CLIENT_EXPIRY, NEIGH_REFRESH_COOLDOWN, NFT_ADD_RETRY_COUNT, NFT_ADD_BACKOFF_MS, NFT_ADD_FAILURE_POLICY, IPC_MATCH_RETRY_ENABLED, IPC_MATCH_RETRY_COUNT, IPC_MATCH_RETRY_SLEEP_MS = _obj_0.QUEUE_RESPONSES, _obj_0.DOCKER_MODE, _obj_0.FORCED_TTL, _obj_0.CLIENT_EXPIRY, _obj_0.NEIGH_REFRESH_COOLDOWN, _obj_0.NFT_ADD_RETRY_COUNT, _obj_0.NFT_ADD_BACKOFF_MS, _obj_0.NFT_ADD_FAILURE_POLICY, _obj_0.IPC_MATCH_RETRY_ENABLED, _obj_0.IPC_MATCH_RETRY_COUNT, _obj_0.IPC_MATCH_RETRY_SLEEP_MS
end
local neigh = require("neigh")
local ndpi = require("parse/ndpi")
local QTYPE
QTYPE = ndpi.QTYPE
local get_l2, ETH_OFFSET
do
  local _obj_0 = require("parse/ethernet")
  get_l2, ETH_OFFSET = _obj_0.get_l2, _obj_0.ETH_OFFSET
end
local drain_pipe, is_pending, get_pending_entry, consume
do
  local _obj_0 = require("ipc")
  drain_pipe, is_pending, get_pending_entry, consume = _obj_0.drain_pipe, _obj_0.is_pending, _obj_0.get_pending_entry, _obj_0.consume
end
local build_refused, build_nxdomain, append_ede_to_dns, EDE_OTHER, EDE_TTL_TEXT, EDNS_OPT_EDE
do
  local _obj_0 = require("parse/dns")
  build_refused, build_nxdomain, append_ede_to_dns, EDE_OTHER, EDE_TTL_TEXT, EDNS_OPT_EDE = _obj_0.build_refused, _obj_0.build_nxdomain, _obj_0.append_ede_to_dns, _obj_0.EDE_OTHER, _obj_0.EDE_TTL_TEXT, _obj_0.EDNS_OPT_EDE
end
local add_ip4, add_ip6, add_mac4, add_mac6
do
  local _obj_0 = require("nft")
  add_ip4, add_ip6, add_mac4, add_mac6 = _obj_0.add_ip4, _obj_0.add_ip6, _obj_0.add_mac4, _obj_0.add_mac6
end
local run_queue, NF_ACCEPT, NF_DROP
do
  local _obj_0 = require("nfq_loop")
  run_queue, NF_ACCEPT, NF_DROP = _obj_0.run_queue, _obj_0.NF_ACCEPT, _obj_0.NF_DROP
end
local log_allow, log_block, log_info, log_warn, now
do
  local _obj_0 = require("log")
  log_allow, log_block, log_info, log_warn, now = _obj_0.log_allow, _obj_0.log_block, _obj_0.log_info, _obj_0.log_warn, _obj_0.now
end
local IPC_RETRY_ENABLED
if IPC_MATCH_RETRY_ENABLED == nil then
  IPC_RETRY_ENABLED = true
else
  IPC_RETRY_ENABLED = IPC_MATCH_RETRY_ENABLED
end
local IPC_RETRY_COUNT = IPC_MATCH_RETRY_COUNT or 5
local IPC_RETRY_SLEEP_MS = IPC_MATCH_RETRY_SLEEP_MS or 20
local MAC_ZERO = "00:00:00:00:00:00"
local mac_valid
mac_valid = function(mac)
  return mac ~= "unknown" and mac ~= MAC_ZERO
end
local try_add_with_retries
try_add_with_retries = require("nft_add_helper").try_add_with_retries
local mac_clients = { }
local ip_to_mac = { }
local pipe_rfd = nil
local last_neigh_refresh = 0
local sleep_req = ffi.new("timespec_t[1]")
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
    if ts - entry.last_seen > CLIENT_EXPIRY then
      if entry.ipv4 then
        ip_to_mac[entry.ipv4] = nil
      end
      if entry.ipv6 then
        ip_to_mac[entry.ipv6] = nil
      end
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
  local ts = os.time()
  if ts - last_neigh_refresh > NEIGH_REFRESH_COOLDOWN then
    last_neigh_refresh = ts
    neigh.refresh(mac_clients, ip_to_mac)
    local mac2 = ip_to_mac[ip_str]
    if mac2 then
      local entry2 = mac_clients[mac2]
      return entry2 and entry2[want]
    end
  end
  return nil
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
  local l2 = get_l2(nfad, raw)
  local pkt, parse_status = ndpi.parse_packet(raw, ETH_OFFSET)
  if not (pkt) then
    if parse_status == "buffering" then
      return NF_DROP
    end
    return NF_ACCEPT
  end
  ndpi.get_flow(pkt)
  if math.random(1000) == 1 then
    ndpi.purge_flows()
    purge_mac_clients(ts)
  end
  if not (pkt.dns.is_response) then
    return NF_ACCEPT
  end
  local client_port = pkt.l4.dst_port
  local txid = pkt.dns.txid
  local client_ip = pkt.ip.dst_ip
  local resolver_ip = pkt.ip.src_ip
  local client_mac = ip_to_mac[client_ip]
  if not (client_mac) then
    client_mac = neigh.get_mac(client_ip)
    if mac_valid(client_mac) then
      last_neigh_refresh = os.time()
      neigh.refresh(mac_clients, ip_to_mac)
    end
  end
  local entry = nil
  if not (DOCKER_MODE) then
    entry = get_pending_entry(txid, pkt.ip.dst_ip, client_port, resolver_ip, now)
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
          retry_wait_ms = retry_wait_ms
        })
      else
        log_block({
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
          retry_wait_ms = retry_wait_ms
        })
        return NF_DROP
      end
    end
    consume(txid, pkt.ip.dst_ip, client_port, resolver_ip)
  end
  local refused = entry and entry.refused or false
  local dnsonly = entry and entry.dnsonly or false
  if refused then
    local dns_raw = ndpi.extract_dns_payload(raw, pkt)
    local refused_dns = build_nxdomain({
      hdr = pkt.dns
    }, dns_raw)
    if not (refused_dns) then
      return NF_DROP
    end
    local patched = ndpi.replace_dns_payload(raw, pkt, refused_dns)
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
    log_block({
      action = "response_refused",
      src_ip = pkt.ip.src_ip,
      dst_ip = pkt.ip.dst_ip,
      vlan = l2.vlan,
      txid = string.format("0x%04x", txid),
      qnames = qnames,
      client_mac = client_mac
    })
    local patched_ptr = ffi.cast("const unsigned char*", patched)
    libnfq.nfq_set_verdict(qh_ptr, pkt_id, NF_ACCEPT, #patched, patched_ptr)
    return -1
  end
  local answers = ndpi.parse_answers(raw, pkt)
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
          local ok = try_add_with_retries(add_ip4, client_v4, ans.rdata_str)
          if ok then
            ip_count = ip_count + 1
          end
          success_any = success_any or ok
        else
          no_ipv4_records[#no_ipv4_records + 1] = ans.rdata_str
        end
        if mac_valid(client_mac) then
          local m_ok = try_add_with_retries(add_mac4, client_mac, ans.rdata_str)
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
          local ok = try_add_with_retries(add_ip6, client_v6, ans.rdata_str)
          if ok then
            ip_count = ip_count + 1
          end
          success_any = success_any or ok
        else
          no_ipv6_records[#no_ipv6_records + 1] = ans.rdata_str
        end
        if mac_valid(client_mac) then
          local m_ok = try_add_with_retries(add_mac6, client_mac, ans.rdata_str)
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
      mac_fallback = mac_valid(client_mac)
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
      mac_fallback = mac_valid(client_mac)
    })
  end
  local dns_raw = ndpi.extract_dns_payload(raw, pkt)
  local new_dns = ndpi.patch_ttl_in_dns(dns_raw, answers, FORCED_TTL)
  local ede_data = string.char(0x00, EDE_OTHER) .. EDE_TTL_TEXT
  new_dns = append_ede_to_dns(new_dns, {
    {
      code = EDNS_OPT_EDE,
      data = ede_data
    }
  }) or new_dns
  local patched = ndpi.replace_dns_payload(raw, pkt, new_dns)
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
  log_allow({
    action = (function()
      if dnsonly then
        return "response_dnsonly"
      else
        return "response_patched"
      end
    end)(),
    src_ip = pkt.ip.src_ip,
    dst_ip = pkt.ip.dst_ip,
    vlan = l2.vlan,
    txid = string.format("0x%04x", txid),
    qnames = qnames,
    answers = ip_count,
    ttl_set = FORCED_TTL,
    rcode = pkt.dns.rcode,
    ndpi_master = pkt.ndpi_master,
    ndpi_app = pkt.ndpi_app,
    client_mac = client_mac
  })
  if records_to_add > 0 and not success_any then
    if NFT_ADD_FAILURE_POLICY == "fail-closed" then
      log_block({
        action = "nft_add_failed_policy_fail_closed",
        txid = string.format("0x%04x", txid),
        client_ip = client_ip,
        qnames = qnames
      })
      return NF_DROP
    else
      log_warn({
        action = "nft_add_failed_fail_open",
        txid = string.format("0x%04x", txid),
        client_ip = client_ip,
        qnames = qnames
      })
    end
  end
  local patched_ptr = ffi.cast("const unsigned char*", patched)
  libnfq.nfq_set_verdict(qh_ptr, pkt_id, NF_ACCEPT, #patched, patched_ptr)
  return -1
end
local run
run = function(rfd)
  pipe_rfd = rfd
  do
    local data = neigh.load()
    mac_clients = data.mac_clients
    ip_to_mac = data.ip_to_mac
  end
  ndpi.warmup()
  run_queue(QUEUE_RESPONSES, handle_response)
  return ndpi.cleanup()
end
return {
  run = run
}
