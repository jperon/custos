local ffi, libnfq
do
  local _obj_0 = require("ffi_defs")
  ffi, libnfq = _obj_0.ffi, _obj_0.libnfq
end
local QUEUE_RESPONSES, DOCKER_MODE, FORCED_TTL, CLIENT_EXPIRY, NEIGH_REFRESH_COOLDOWN
do
  local _obj_0 = require("config")
  QUEUE_RESPONSES, DOCKER_MODE, FORCED_TTL, CLIENT_EXPIRY, NEIGH_REFRESH_COOLDOWN = _obj_0.QUEUE_RESPONSES, _obj_0.DOCKER_MODE, _obj_0.FORCED_TTL, _obj_0.CLIENT_EXPIRY, _obj_0.NEIGH_REFRESH_COOLDOWN
end
local neigh = require("neigh")
local ndpi = require("parse/ndpi")
local QTYPE
QTYPE = ndpi.QTYPE
local drain_pipe, is_pending, consume
do
  local _obj_0 = require("ipc")
  drain_pipe, is_pending, consume = _obj_0.drain_pipe, _obj_0.is_pending, _obj_0.consume
end
local add_ip4, add_ip6
do
  local _obj_0 = require("nft")
  add_ip4, add_ip6 = _obj_0.add_ip4, _obj_0.add_ip6
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
local last_neigh_refresh = 0
local update_mac_clients = nil
local drain_ts = 0
local drain_on_msg
drain_on_msg = function(msg)
  return update_mac_clients(msg, drain_ts)
end
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
  local client_v4 = nil
  local client_v6 = nil
  local ip_count = 0
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
      if client_v4 then
        add_ip4(client_v4, ans.rdata_str)
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
      client_v6 = client_v6 or (function()
        if pkt.ip.version == 6 then
          return client_ip
        else
          return resolve_client_family(client_ip, "ipv6")
        end
      end)()
      if client_v6 then
        add_ip6(client_v6, ans.rdata_str)
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
