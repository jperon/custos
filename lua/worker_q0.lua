local ffi, libc, libnfq
do
  local _obj_0 = require("ffi_defs")
  ffi, libc, libnfq = _obj_0.ffi, _obj_0.libc, _obj_0.libnfq
end
local QUEUE_QUESTIONS
QUEUE_QUESTIONS = require("config").QUEUE_QUESTIONS
local get_l2
get_l2 = require("parse/ethernet").get_l2
local ndpi = require("parse/ndpi")
local is_allowed, check_reload
do
  local _obj_0 = require("allowlist")
  is_allowed, check_reload = _obj_0.is_allowed, _obj_0.check_reload
end
local write_msg
write_msg = require("ipc").write_msg
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
local build_refused
build_refused = require("parse/dns").build_refused
local refuse = require("refuse")
local pipe_wfd = nil
local handle_question
handle_question = function(qh_ptr, nfad, pkt_id)
  check_reload()
  local l2 = get_l2(nfad)
  local payload_ptr = ffi.new("unsigned char*[1]")
  local payload_len = libnfq.nfq_get_payload(nfad, payload_ptr)
  if payload_len <= 0 then
    return NF_DROP
  end
  local raw = ffi.string(payload_ptr[0], payload_len)
  local pkt = ndpi.parse_packet(raw)
  if not (pkt) then
    log_warn({
      action = "parse_failed",
      mac_src = l2.mac_src
    })
    return NF_ACCEPT
  end
  if pkt.dns.is_response then
    return NF_ACCEPT
  end
  local verdict = NF_ACCEPT
  local q_fields = {
    mac_src = l2.mac_src,
    in_if = tostring(l2.in_ifindex),
    src_ip = pkt.ip.src_ip,
    dst_ip = pkt.ip.dst_ip,
    src_port = pkt.udp.src_port,
    dst_port = pkt.udp.dst_port,
    txid = string.format("0x%04x", pkt.dns.txid),
    af = pkt.ip.version == 6 and "ipv6" or "ipv4",
    ndpi_master = pkt.ndpi_master,
    ndpi_app = pkt.ndpi_app
  }
  for _, q in ipairs(pkt.questions) do
    if is_allowed(q.qname) then
      log_allow({
        unpack((function()
          local _tbl_0 = { }
          for k, v in pairs(q_fields) do
            _tbl_0[k] = v
          end
          return _tbl_0
        end)()),
        qname = q.qname,
        qtype = q.qtype_name
      })
    else
      log_block({
        unpack((function()
          local _tbl_0 = { }
          for k, v in pairs(q_fields) do
            _tbl_0[k] = v
          end
          return _tbl_0
        end)()),
        qname = q.qname,
        qtype = q.qtype_name,
        reason = "not_in_allowlist"
      })
      verdict = NF_DROP
    end
  end
  if verdict == NF_ACCEPT then
    write_msg(pipe_wfd, pkt.dns.txid, pkt.ip.src_ip_raw, pkt.udp.src_port)
  end
  if verdict == NF_DROP then
    local dns_raw = raw:sub(pkt.udp.payload_off + 1, pkt.udp.payload_off + pkt.udp.payload_len)
    local refused_payload = build_refused({
      hdr = pkt.dns
    }, dns_raw)
    if refused_payload then
      refuse.send_refused(pkt.ip.src_ip_raw, pkt.udp.src_port, refused_payload, pkt.ip.af)
    end
  end
  return verdict
end
local run
run = function(wfd)
  pipe_wfd = wfd
  refuse.init()
  ndpi.warmup()
  run_queue(QUEUE_QUESTIONS, handle_question)
  return ndpi.cleanup()
end
return {
  run = run
}
