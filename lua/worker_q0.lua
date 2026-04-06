local ffi, libc, libnfq
do
  local _obj_0 = require("ffi_defs")
  ffi, libc, libnfq = _obj_0.ffi, _obj_0.libc, _obj_0.libnfq
end
local QUEUE_QUESTIONS
QUEUE_QUESTIONS = require("config").QUEUE_QUESTIONS
local get_l2
get_l2 = require("parse/ethernet").get_l2
local parse_ip
parse_ip = require("parse/ip").parse_ip
local parse_udp
parse_udp = require("parse/udp").parse_udp
local parse_dns
parse_dns = require("parse/dns").parse_dns
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
  local ip_hdr = parse_ip(raw)
  if not (ip_hdr) then
    log_warn({
      action = "parse_ip_failed",
      mac_src = l2.mac_src
    })
    return NF_ACCEPT
  end
  local udp_hdr = parse_udp(raw, ip_hdr)
  if not (udp_hdr) then
    log_warn({
      action = "parse_udp_failed",
      src = ip_hdr.src_ip
    })
    return NF_ACCEPT
  end
  local dns = parse_dns(udp_hdr.dns_payload)
  if not (dns) then
    log_warn({
      action = "parse_dns_failed",
      src = ip_hdr.src_ip
    })
    return NF_ACCEPT
  end
  if dns.hdr.is_response then
    return NF_ACCEPT
  end
  local verdict = NF_ACCEPT
  local q_fields = {
    mac_src = l2.mac_src,
    in_if = tostring(l2.in_ifindex),
    src_ip = ip_hdr.src_ip,
    dst_ip = ip_hdr.dst_ip,
    src_port = udp_hdr.src_port,
    dst_port = udp_hdr.dst_port,
    txid = string.format("0x%04x", dns.hdr.txid),
    af = ip_hdr.version == 6 and "ipv6" or "ipv4"
  }
  for _, q in ipairs(dns.questions) do
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
    write_msg(pipe_wfd, dns.hdr.txid, ip_hdr.src_ip_raw, udp_hdr.src_port)
  end
  if verdict == NF_DROP then
    local refused_payload = build_refused(dns, udp_hdr.dns_payload)
    if refused_payload then
      refuse.send_refused(ip_hdr.src_ip_raw, udp_hdr.src_port, refused_payload, ip_hdr.af)
    end
  end
  return verdict
end
local run
run = function(wfd)
  pipe_wfd = wfd
  refuse.init()
  return run_queue(QUEUE_QUESTIONS, handle_question)
end
return {
  run = run
}
