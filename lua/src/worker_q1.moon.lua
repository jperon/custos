local ffi, libc, libnfq
do
  local _obj_0 = require("ffi_defs")
  ffi, libc, libnfq = _obj_0.ffi, _obj_0.libc, _obj_0.libnfq
end
local QUEUE_RESPONSES, DOCKER_MODE
do
  local _obj_0 = require("config")
  QUEUE_RESPONSES, DOCKER_MODE = _obj_0.QUEUE_RESPONSES, _obj_0.DOCKER_MODE
end
local parse_ip
parse_ip = require("parse/ip").parse_ip
local parse_udp, checksum_udp
do
  local _obj_0 = require("parse/udp")
  parse_udp, checksum_udp = _obj_0.parse_udp, _obj_0.checksum_udp
end
local parse_dns, patch_ttl, QTYPE
do
  local _obj_0 = require("parse/dns")
  parse_dns, patch_ttl, QTYPE = _obj_0.parse_dns, _obj_0.patch_ttl, _obj_0.QTYPE
end
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
local log_allow, log_block, log_info, log_warn, now
do
  local _obj_0 = require("log")
  log_allow, log_block, log_info, log_warn, now = _obj_0.log_allow, _obj_0.log_block, _obj_0.log_info, _obj_0.log_warn, _obj_0.now
end
local bit = require("bit")
local FORCED_TTL = 60
local pipe_rfd = nil
local patch_packet
patch_packet = function(raw, ip_hdr, udp_hdr, dns)
  local pkt_len = #raw
  local buf = ffi.new("uint8_t[?]", pkt_len)
  ffi.copy(buf, raw, pkt_len)
  local dns_offset_0 = ip_hdr.ihl + 8
  patch_ttl(buf, dns.answers, dns_offset_0, FORCED_TTL)
  local patched_raw = ffi.string(buf, pkt_len)
  local new_udp_cksum = checksum_udp(patched_raw, ip_hdr, udp_hdr)
  local cksum_off = udp_hdr.udp_off + 6 - 1
  buf[cksum_off] = bit.rshift(bit.band(new_udp_cksum, 0xFF00), 8)
  buf[cksum_off + 1] = bit.band(new_udp_cksum, 0xFF)
  buf[10] = 0
  buf[11] = 0
  local ip_header_str = ffi.string(buf, ip_hdr.ihl)
  local checksum_ip
  checksum_ip = require("parse/ip").checksum_ip
  local new_ip_cksum = checksum_ip(ip_header_str)
  buf[10] = bit.rshift(bit.band(new_ip_cksum, 0xFF00), 8)
  buf[11] = bit.band(new_ip_cksum, 0xFF)
  return ffi.string(buf, pkt_len)
end
local handle_response
handle_response = function(qh_ptr, nfad, pkt_id)
  log_warn({
    action = "q1_entry",
    pkt_id = tonumber(pkt_id)
  })
  log_warn({
    action = "q1_before_drain"
  })
  drain_pipe(pipe_rfd, now)
  log_warn({
    action = "q1_after_drain"
  })
  local payload_ptr = ffi.new("unsigned char*[1]")
  local payload_len = libnfq.nfq_get_payload(nfad, payload_ptr)
  if payload_len <= 0 then
    log_warn({
      action = "q1_no_payload"
    })
    return NF_DROP
  end
  local raw = ffi.string(payload_ptr[0], payload_len)
  local ip_hdr = parse_ip(raw)
  if not (ip_hdr) then
    log_warn({
      action = "q1_no_ip",
      pkt_len = #raw
    })
    return NF_ACCEPT
  end
  local udp_hdr = parse_udp(raw, ip_hdr)
  if not (udp_hdr) then
    log_warn({
      action = "q1_no_udp",
      src = ip_hdr.src_ip,
      dst = ip_hdr.dst_ip
    })
    return NF_ACCEPT
  end
  local dns = parse_dns(udp_hdr.dns_payload)
  if not (dns) then
    log_warn({
      action = "q1_no_dns",
      src = ip_hdr.src_ip
    })
    return NF_ACCEPT
  end
  if not (dns.hdr.is_response) then
    log_warn({
      action = "q1_not_response",
      src = ip_hdr.src_ip
    })
    return NF_ACCEPT
  end
  local client_ip = ip_hdr.dst_ip_raw
  local client_port = udp_hdr.dst_port
  local txid = dns.hdr.txid
  if not (DOCKER_MODE) then
    if not (is_pending(txid, ip_hdr.dst_ip, client_port, now)) then
      log_block({
        action = "response_no_matching_question",
        src_ip = ip_hdr.src_ip,
        dst_ip = ip_hdr.dst_ip,
        txid = string.format("0x%04x", txid),
        rcode = dns.hdr.rcode
      })
      return NF_DROP
    end
    consume(txid, ip_hdr.dst_ip, client_port)
  end
  local ip_count = 0
  local _list_0 = dns.answers
  for _index_0 = 1, #_list_0 do
    local ans = _list_0[_index_0]
    if ans.rtype == QTYPE.A or ans.rtype == QTYPE.AAAA then
      log_warn({
        action = "q1_add_ip",
        ip = ans.rdata_str
      })
      add_ip(ans.rdata_str)
      log_warn({
        action = "q1_add_ip_done",
        ip = ans.rdata_str
      })
      ip_count = ip_count + 1
    end
  end
  log_warn({
    action = "q1_patch_start"
  })
  local patched = patch_packet(raw, ip_hdr, udp_hdr, dns)
  log_warn({
    action = "q1_patch_done"
  })
  local qnames = table.concat((function()
    local _accum_0 = { }
    local _len_0 = 1
    local _list_1 = dns.questions
    for _index_0 = 1, #_list_1 do
      local q = _list_1[_index_0]
      _accum_0[_len_0] = q.qname
      _len_0 = _len_0 + 1
    end
    return _accum_0
  end)(), ",")
  log_allow({
    action = "response_patched",
    src_ip = ip_hdr.src_ip,
    dst_ip = ip_hdr.dst_ip,
    txid = string.format("0x%04x", txid),
    qnames = qnames,
    answers = ip_count,
    ttl_set = FORCED_TTL,
    rcode = dns.hdr.rcode
  })
  local patched_ptr = ffi.cast("const unsigned char*", patched)
  libnfq.nfq_set_verdict(qh_ptr, pkt_id, NF_ACCEPT, #patched, patched_ptr)
  return -1
end
local run
run = function(rfd)
  pipe_rfd = rfd
  return run_queue(QUEUE_RESPONSES, handle_response)
end
return {
  run = run
}
