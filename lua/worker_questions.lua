local ffi, libc, libnfq
do
  local _obj_0 = require("ffi_defs")
  ffi, libc, libnfq = _obj_0.ffi, _obj_0.libc, _obj_0.libnfq
end
local QUEUE_QUESTIONS, AUTH_SESSIONS_FILE, BENCHMARK
do
  local _obj_0 = require("config")
  QUEUE_QUESTIONS, AUTH_SESSIONS_FILE, BENCHMARK = _obj_0.QUEUE_QUESTIONS, _obj_0.AUTH_SESSIONS_FILE, _obj_0.BENCHMARK
end
local get_l2
get_l2 = require("parse/ethernet").get_l2
local packet = require("parse/ndpi")
local filter = require("filter")
local write_msg, write_refused_msg, write_dnsonly_msg
do
  local _obj_0 = require("ipc")
  write_msg, write_refused_msg, write_dnsonly_msg = _obj_0.write_msg, _obj_0.write_refused_msg, _obj_0.write_dnsonly_msg
end
local run_queue, NF_ACCEPT, NF_DROP
do
  local _obj_0 = require("nfq_loop")
  run_queue, NF_ACCEPT, NF_DROP = _obj_0.run_queue, _obj_0.NF_ACCEPT, _obj_0.NF_DROP
end
local log_allow, log_block, log_warn, log_debug, log_info, set_action_prefix
do
  local _obj_0 = require("log")
  log_allow, log_block, log_warn, log_debug, log_info, set_action_prefix = _obj_0.log_allow, _obj_0.log_block, _obj_0.log_warn, _obj_0.log_debug, _obj_0.log_info, _obj_0.set_action_prefix
end
local user_for_mac
user_for_mac = require("auth.sessions").user_for_mac
local forge_dns = require("forge_dns")
local detect_captive_ips
detect_captive_ips = require("captive_ips").detect
local bridge_raw = require("bridge_raw")
local new_eth, IP4, IP6
do
  local _obj_0 = require("ipparse.l2.ethernet")
  new_eth, IP4, IP6 = _obj_0.new, _obj_0.proto.IP4, _obj_0.proto.IP6
end
local pipe_wfd = nil
local mac_learn_wfd = nil
local _benchmark_ts = ffi.new("timespec_t[1]")
local CLOCK_MONOTONIC = 1
local get_benchmark_ms
get_benchmark_ms = function()
  if not (BENCHMARK) then
    return nil
  end
  libc.clock_gettime(CLOCK_MONOTONIC, _benchmark_ts)
  return tonumber(_benchmark_ts[0].tv_sec) * 1000 + math.floor(tonumber(_benchmark_ts[0].tv_nsec) / 1000000)
end
local events_wfd = nil
local captive_domain = nil
local captive_ip4 = nil
local captive_ip6 = nil
local raw_fd = nil
local _ifindex = nil
local _bridge_mac = nil
local domain_from_url
domain_from_url = function(url)
  if not (url) then
    return nil
  end
  local host = url:match("^https?://([^/:]+)")
  if not (host) then
    return nil
  end
  if host:match("^%d+%.%d+%.%d+%.%d+$") then
    return nil
  end
  if host:match("^%[") then
    return nil
  end
  return host:lower()
end
local write_learn_msg
write_learn_msg = function(ip_raw, mac_raw)
  if not (mac_learn_wfd and mac_learn_wfd >= 0) then
    return false
  end
  if not (ip_raw and (#ip_raw == 4 or #ip_raw == 16)) then
    return false
  end
  if not (mac_raw and #mac_raw == 6) then
    return false
  end
  local msg = ffi.new("uint8_t[22]")
  if #ip_raw == 4 then
    for i = 1, 4 do
      msg[i - 1] = ip_raw:byte(i)
    end
  else
    for i = 1, 16 do
      msg[i - 1] = ip_raw:byte(i)
    end
  end
  for i = 1, 6 do
    msg[15 + i] = mac_raw:byte(i)
  end
  local n = libc.write(mac_learn_wfd, msg, 22)
  return n == 22
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
local write_event
write_event = function(fields, allowed)
  if not (events_wfd) then
    return 
  end
  local decision
  if allowed == "dnsonly" then
    decision = "dnsonly"
  elseif allowed then
    decision = "allow"
  else
    decision = "block"
  end
  local line = table.concat({
    tostring(os.time()),
    decision,
    tsv_field(fields.qname),
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
local handle_question
handle_question = function(qh_ptr, nfad, pkt_id)
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
      return NF_ACCEPT
    end
    if parse_status == "tcp_control" then
      return NF_ACCEPT
    end
    log_warn({
      action = "parse_failed",
      mac_src = l2.mac_src,
      status = parse_status
    })
    return NF_DROP
  end
  if l2.mac_src == "unknown" then
    log_warn({
      action = "l2_mac_missing",
      src_ip = pkt.ip.src_ip,
      in_ifindex = l2.in_ifindex,
      vlan = l2.vlan
    })
  else
    log_debug({
      action = "l2_info",
      mac_src = l2.mac_src,
      src_ip = pkt.ip.src_ip,
      in_ifindex = l2.in_ifindex,
      vlan = l2.vlan
    })
  end
  if pkt.dns.is_response then
    return NF_ACCEPT
  end
  write_learn_msg(pkt.ip.src_ip_raw, l2.mac_raw)
  if captive_domain and raw_fd and _bridge_mac then
    for _, q in ipairs(pkt.questions) do
      local norm = q.qname:lower():gsub("%.+$", "")
      if norm == captive_domain and (q.qtype == 1 or q.qtype == 28) then
        local mac_raw = l2.mac_raw
        if not mac_raw or mac_raw == "\0\0\0\0\0\0" then
          log_warn({
            action = "dns_steal_no_mac",
            domain = q.qname,
            src_ip = pkt.ip.src_ip
          })
          break
        end
        local forged_ip = forge_dns.forge_dns_response(pkt, q, captive_ip4, captive_ip6)
        if forged_ip then
          local eth_obj = new_eth({
            src = _bridge_mac,
            dst = mac_raw,
            protocol = pkt.ip.version == 6 and IP6 or IP4,
            data = forged_ip
          })
          local ok = bridge_raw.send(raw_fd, tostring(eth_obj), _ifindex)
          log_info({
            action = "dns_stolen",
            domain = q.qname,
            qtype = q.qtype_name,
            src_ip = pkt.ip.src_ip,
            resolver = pkt.ip.dst_ip,
            mac = l2.mac_src,
            ancount = (captive_ip4 and q.qtype == 1 or captive_ip6 and q.qtype == 28) and 1 or 0,
            sent = ok
          })
          return NF_DROP
        else
          log_warn({
            action = "dns_steal_forge_failed",
            domain = q.qname,
            qtype = q.qtype_name,
            src_ip = pkt.ip.src_ip
          })
          break
        end
      end
    end
  end
  local verdict = NF_ACCEPT
  local dnsonly = false
  local block_reason = nil
  local allow_reason = nil
  local q_fields = {
    mac_src = l2.mac_src,
    vlan = l2.vlan,
    in_if = tostring(l2.in_ifindex),
    src_ip = pkt.ip.src_ip,
    dst_ip = pkt.ip.dst_ip,
    src_port = pkt.l4.src_port,
    dst_port = pkt.l4.dst_port,
    txid = string.format("0x%04x", pkt.dns.txid),
    af = pkt.ip.version == 6 and "ipv6" or "ipv4",
    user = user_for_mac(l2.mac_src, pkt.ip.src_ip, AUTH_SESSIONS_FILE)
  }
  for _, q in ipairs(pkt.questions) do
    q_fields.qname = q.qname
    q_fields.qtype = q.qtype_name
    local req = {
      domain = q.qname,
      src_ip = pkt.ip.src_ip,
      mac = l2.mac_src,
      vlan = l2.vlan,
      ts = os.time()
    }
    local allowed, reason, rule = filter.decide(req)
    q_fields.reason = reason or (allowed == "dnsonly" and "dnsonly") or (allowed and "allowed") or "denied"
    q_fields.rule = rule or ""
    if allowed == "dnsonly" then
      log_allow(q_fields)
      dnsonly = true
      allow_reason = reason
    elseif allowed then
      log_allow(q_fields)
      allow_reason = reason
    else
      log_block(q_fields)
      verdict = NF_DROP
      block_reason = reason
    end
    write_event(q_fields, allowed)
  end
  local benchmark_ms = get_benchmark_ms()
  local ipc_ok = false
  if verdict == NF_ACCEPT then
    if dnsonly then
      ipc_ok = write_dnsonly_msg(pipe_wfd, pkt.dns.txid, pkt.ip.src_ip_raw, pkt.l4.src_port, l2.mac_raw, pkt.ip.dst_ip_raw, allow_reason, benchmark_ms)
    else
      ipc_ok = write_msg(pipe_wfd, pkt.dns.txid, pkt.ip.src_ip_raw, pkt.l4.src_port, l2.mac_raw, pkt.ip.dst_ip_raw, allow_reason, benchmark_ms)
    end
  else
    ipc_ok = write_refused_msg(pipe_wfd, pkt.dns.txid, pkt.ip.src_ip_raw, pkt.l4.src_port, l2.mac_raw, pkt.ip.dst_ip_raw, block_reason, benchmark_ms)
  end
  if not (ipc_ok) then
    log_warn({
      action = "ipc_write_failed",
      txid = string.format("0x%04x", pkt.dns.txid),
      src_ip = pkt.ip.src_ip,
      dst_ip = pkt.ip.dst_ip,
      src_port = pkt.l4.src_port,
      user = q_fields.user
    })
    return NF_DROP
  end
  return NF_ACCEPT
end
local run
run = function(queue_num, wfd, learn_wfd, ev_wfd)
  set_action_prefix("questions_")
  pipe_wfd = wfd
  mac_learn_wfd = learn_wfd
  events_wfd = ev_wfd
  do
    local auth = filter.get_auth_cfg()
    captive_domain = domain_from_url(auth.redirect_url)
    captive_ip4, captive_ip6 = detect_captive_ips(auth)
    if captive_domain then
      local ifname = auth.bridge_ifname or os.getenv("BRIDGE_IFNAME") or "br"
      local fd, err = bridge_raw.open_socket(ifname)
      if fd then
        raw_fd = fd
        _ifindex = tonumber(ffi.C.if_nametoindex(ifname))
        _bridge_mac = bridge_raw.read_mac(ifname)
        log_info({
          action = "dns_steal_armed",
          domain = captive_domain,
          captive_ip4 = captive_ip4 or "none",
          captive_ip6 = captive_ip6 or "none",
          ifname = ifname
        })
      else
        log_warn({
          action = "dns_steal_socket_failed",
          err = err,
          ifname = ifname,
          errno = tonumber(ffi.C.__errno_location()[0]) or 0
        })
      end
    else
      log_info({
        action = "dns_steal_disabled",
        reason = "no hostname in redirect_url"
      })
    end
  end
  return run_queue(tonumber(queue_num), handle_question)
end
return {
  run = run
}
