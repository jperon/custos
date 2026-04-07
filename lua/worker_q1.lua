local ffi, libc, libnfq
do
  local _obj_0 = require("ffi_defs")
  ffi, libc, libnfq = _obj_0.ffi, _obj_0.libc, _obj_0.libnfq
end
local QUEUE_RESPONSES, DOCKER_MODE, FORCED_TTL, CLIENT_EXPIRY
do
  local _obj_0 = require("config")
  QUEUE_RESPONSES, DOCKER_MODE, FORCED_TTL, CLIENT_EXPIRY = _obj_0.QUEUE_RESPONSES, _obj_0.DOCKER_MODE, _obj_0.FORCED_TTL, _obj_0.CLIENT_EXPIRY
end
local ndpi = require("parse/ndpi")
local QTYPE
QTYPE = ndpi.QTYPE
local drain_pipe, is_pending, consume
do
  local _obj_0 = require("ipc")
  drain_pipe, is_pending, consume = _obj_0.drain_pipe, _obj_0.is_pending, _obj_0.consume
end
local add_ip, add_ip4, add_ip6
do
  local _obj_0 = require("nft")
  add_ip, add_ip4, add_ip6 = _obj_0.add_ip, _obj_0.add_ip4, _obj_0.add_ip6
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
local MAC_ZERO = "00:00:00:00:00:00"
local mac_clients = { }
local ip_to_mac = { }
local pipe_rfd = nil
local update_mac_clients
update_mac_clients = function(msg, ts)
  local mac = msg.mac_str
  if mac == MAC_ZERO then
    return 
  end
  local entry = mac_clients[mac] or { }
  entry.last_seen = ts
  if msg.msg_type == 0x41 then
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
  if not (mac) then
    return nil
  end
  local entry = mac_clients[mac]
  if not (entry) then
    return nil
  end
  return entry[want]
end
local handle_response
handle_response = function(qh_ptr, nfad, pkt_id)
  local ts = now()
  drain_pipe(pipe_rfd, now, function(msg)
    return update_mac_clients(msg, ts)
  end)
  local payload_ptr = ffi.new("unsigned char*[1]")
  local payload_len = libnfq.nfq_get_payload(nfad, payload_ptr)
  if payload_len <= 0 then
    return NF_DROP
  end
  local raw = ffi.string(payload_ptr[0], payload_len)
  local pkt, parse_status = ndpi.parse_packet(raw)
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
  if not (DOCKER_MODE) then
    if not (is_pending(txid, pkt.ip.dst_ip, client_port, now)) then
      log_block({
        action = "response_no_matching_question",
        src_ip = pkt.ip.src_ip,
        dst_ip = pkt.ip.dst_ip,
        txid = string.format("0x%04x", txid),
        rcode = pkt.dns.rcode
      })
      return NF_DROP
    end
    consume(txid, pkt.ip.dst_ip, client_port)
  end
  local answers = ndpi.parse_answers(raw, pkt)
  local client_ip = pkt.ip.dst_ip
  local ip_count = 0
  for _index_0 = 1, #answers do
    local ans = answers[_index_0]
    if ans.rtype == QTYPE.A then
      local c4
      if pkt.ip.version == 4 then
        c4 = client_ip
      else
        c4 = resolve_client_family(client_ip, "ipv4")
      end
      if c4 then
        add_ip4(c4, ans.rdata_str)
        ip_count = ip_count + 1
      else
        log_warn({
          action = "no_ipv4_for_client",
          client = client_ip,
          record = ans.rdata_str,
          reason = "mac_not_known"
        })
      end
    elseif ans.rtype == QTYPE.AAAA then
      local c6
      if pkt.ip.version == 6 then
        c6 = client_ip
      else
        c6 = resolve_client_family(client_ip, "ipv6")
      end
      if c6 then
        add_ip6(c6, ans.rdata_str)
        ip_count = ip_count + 1
      else
        log_warn({
          action = "no_ipv6_for_client",
          client = client_ip,
          record = ans.rdata_str,
          reason = "mac_not_known"
        })
      end
    end
  end
  local patched = ndpi.patch_and_checksum(raw, pkt, answers, FORCED_TTL)
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
    action = "response_patched",
    src_ip = pkt.ip.src_ip,
    dst_ip = pkt.ip.dst_ip,
    txid = string.format("0x%04x", txid),
    qnames = qnames,
    answers = ip_count,
    ttl_set = FORCED_TTL,
    rcode = pkt.dns.rcode,
    ndpi_master = pkt.ndpi_master,
    ndpi_app = pkt.ndpi_app
  })
  local patched_ptr = ffi.cast("const unsigned char*", patched)
  libnfq.nfq_set_verdict(qh_ptr, pkt_id, NF_ACCEPT, #patched, patched_ptr)
  return -1
end
local run
run = function(rfd)
  pipe_rfd = rfd
  ndpi.warmup()
  run_queue(QUEUE_RESPONSES, handle_response)
  return ndpi.cleanup()
end
return {
  run = run
}
