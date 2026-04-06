local ffi, libc, libnfq
do
  local _obj_0 = require("ffi_defs")
  ffi, libc, libnfq = _obj_0.ffi, _obj_0.libc, _obj_0.libnfq
end
local QUEUE_RESPONSES, DOCKER_MODE, FORCED_TTL
do
  local _obj_0 = require("config")
  QUEUE_RESPONSES, DOCKER_MODE, FORCED_TTL = _obj_0.QUEUE_RESPONSES, _obj_0.DOCKER_MODE, _obj_0.FORCED_TTL
end
local ndpi = require("parse/ndpi")
local QTYPE
QTYPE = ndpi.QTYPE
local drain_pipe, is_pending, consume
do
  local _obj_0 = require("ipc")
  drain_pipe, is_pending, consume = _obj_0.drain_pipe, _obj_0.is_pending, _obj_0.consume
end
local add_ip
add_ip = require("nft").add_ip
local run_queue, NF_ACCEPT, NF_DROP
do
  local _obj_0 = require("nfq_loop")
  run_queue, NF_ACCEPT, NF_DROP = _obj_0.run_queue, _obj_0.NF_ACCEPT, _obj_0.NF_DROP
end
local log_allow, log_block, log_info, now
do
  local _obj_0 = require("log")
  log_allow, log_block, log_info, now = _obj_0.log_allow, _obj_0.log_block, _obj_0.log_info, _obj_0.now
end
local pipe_rfd = nil
local handle_response
handle_response = function(qh_ptr, nfad, pkt_id)
  drain_pipe(pipe_rfd, now)
  local payload_ptr = ffi.new("unsigned char*[1]")
  local payload_len = libnfq.nfq_get_payload(nfad, payload_ptr)
  if payload_len <= 0 then
    return NF_DROP
  end
  local raw = ffi.string(payload_ptr[0], payload_len)
  local pkt = ndpi.parse_packet(raw)
  if not (pkt) then
    return NF_ACCEPT
  end
  if not (pkt.dns.is_response) then
    return NF_ACCEPT
  end
  local client_port = pkt.udp.dst_port
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
  local ip_count = 0
  for _index_0 = 1, #answers do
    local ans = answers[_index_0]
    if ans.rtype == QTYPE.A or ans.rtype == QTYPE.AAAA then
      add_ip(ans.rdata_str)
      ip_count = ip_count + 1
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
