local ffi, libnfq
do
  local _obj_0 = require("ffi_defs")
  ffi, libnfq = _obj_0.ffi, _obj_0.libnfq
end
local QUEUE_QUESTIONS, AUTH_SESSIONS_FILE
do
  local _obj_0 = require("config")
  QUEUE_QUESTIONS, AUTH_SESSIONS_FILE = _obj_0.QUEUE_QUESTIONS, _obj_0.AUTH_SESSIONS_FILE
end
local get_l2
get_l2 = require("parse/ethernet").get_l2
local ndpi = require("parse/ndpi")
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
local log_allow, log_block, log_warn
do
  local _obj_0 = require("log")
  log_allow, log_block, log_warn = _obj_0.log_allow, _obj_0.log_block, _obj_0.log_warn
end
local user_for_mac
user_for_mac = require("auth.sessions").user_for_mac
local neigh = require("neigh")
local pipe_wfd = nil
local handle_question
handle_question = function(qh_ptr, nfad, pkt_id)
  filter.reload()
  local payload_ptr = ffi.new("unsigned char*[1]")
  local payload_len = libnfq.nfq_get_payload(nfad, payload_ptr)
  if payload_len <= 0 then
    return NF_DROP
  end
  local raw = ffi.string(payload_ptr[0], payload_len)
  local l2 = get_l2(nfad)
  local pkt, parse_status = ndpi.parse_packet(raw)
  if not (pkt) then
    if parse_status == "buffering" then
      return NF_ACCEPT
    end
    if parse_status == "tcp_control" then
      return NF_ACCEPT
    end
    log_warn({
      action = "parse_failed",
      mac_src = l2.mac_src
    })
    return NF_DROP
  end
  if l2.mac_src == "unknown" or not l2.mac_src then
    l2.mac_src = neigh.get_mac(pkt.ip.src_ip)
  end
  ndpi.get_flow(pkt)
  if math.random(1000) == 1 then
    ndpi.purge_flows()
  end
  if pkt.dns.is_response then
    return NF_ACCEPT
  end
  local verdict = NF_ACCEPT
  local dnsonly = false
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
    ndpi_master = pkt.ndpi_master,
    ndpi_app = pkt.ndpi_app,
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
    elseif allowed then
      log_allow(q_fields)
    else
      log_block(q_fields)
      verdict = NF_DROP
    end
  end
  local ipc_ok = false
  if verdict == NF_ACCEPT then
    if dnsonly then
      ipc_ok = write_dnsonly_msg(pipe_wfd, pkt.dns.txid, pkt.ip.src_ip_raw, pkt.l4.src_port, l2.mac_raw, pkt.ip.dst_ip_raw)
    else
      ipc_ok = write_msg(pipe_wfd, pkt.dns.txid, pkt.ip.src_ip_raw, pkt.l4.src_port, l2.mac_raw, pkt.ip.dst_ip_raw)
    end
  else
    ipc_ok = write_refused_msg(pipe_wfd, pkt.dns.txid, pkt.ip.src_ip_raw, pkt.l4.src_port, l2.mac_raw, pkt.ip.dst_ip_raw)
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
run = function(wfd)
  pipe_wfd = wfd
  filter.load()
  ndpi.warmup()
  local nft_extra = require("nft_extra_rules")
  nft_extra.apply_from_config()
  run_queue(QUEUE_QUESTIONS, handle_question)
  nft_extra.cleanup()
  return ndpi.cleanup()
end
return {
  run = run
}
