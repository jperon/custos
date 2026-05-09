local ffi, libnfq
do
  local _obj_0 = require("ffi_defs")
  ffi, libnfq = _obj_0.ffi, _obj_0.libnfq
end
local run_queue, NF_ACCEPT, NF_DROP, VERDICT_DONE
do
  local _obj_0 = require("nfq_loop")
  run_queue, NF_ACCEPT, NF_DROP, VERDICT_DONE = _obj_0.run_queue, _obj_0.NF_ACCEPT, _obj_0.NF_DROP, _obj_0.VERDICT_DONE
end
local log_info, log_warn, log_debug, set_action_prefix
do
  local _obj_0 = require("log")
  log_info, log_warn, log_debug, set_action_prefix = _obj_0.log_info, _obj_0.log_warn, _obj_0.log_debug, _obj_0.set_action_prefix
end
local parse_ip, new_ip, ip_proto
do
  local _obj_0 = require("ipparse.l3.ip")
  parse_ip, new_ip, ip_proto = _obj_0.parse, _obj_0.new, _obj_0.proto
end
local parse_tcp
parse_tcp = require("ipparse.l4.tcp").parse
local parse_udp
parse_udp = require("ipparse.l4.udp").parse
local flags
flags = require("ipparse.l4.tcp").flags
local RST, ACK
RST, ACK = flags.RST, flags.ACK
local ip2s
ip2s = require("ipparse.l3.ip").ip2s
local sp
sp = require("ipparse.lib.pack_compat").pack
local checksum
checksum = require("ipparse.l3.lib").checksum
local PROTO_TCP = ip_proto.TCP
local PROTO_UDP = ip_proto.UDP
local PROTO_ICMP = ip_proto.ICMP
local PROTO_ICMPv6 = ip_proto.ICMPv6
local ICMP4_TYPE = 3
local ICMP4_CODE = 13
local ICMP6_TYPE = 1
local ICMP6_CODE = 1
local ICMP_QUOTE_MAX = 576
local forge_tcp_rst
forge_tcp_rst = function(ip, tcp)
  local rst = {
    spt = tcp.dpt,
    dpt = tcp.spt,
    seq_n = 0,
    ack_n = (tcp.seq_n + 1) % 0x100000000,
    header_len = 0x50,
    flags = RST + ACK,
    window = 0,
    checksum = 0,
    urg_ptr = 0,
    options = "",
    data = ""
  }
  local rst_obj = (require("ipparse.l4.tcp")).new(rst)
  local ip_obj
  if ip.version == 6 then
    ip_obj = new_ip({
      version = 6,
      hop_limit = 64,
      next_header = PROTO_TCP,
      src = ip.dst,
      dst = ip.src,
      options = "",
      data = rst_obj
    })
  else
    ip_obj = new_ip({
      version = 4,
      ttl = 64,
      protocol = PROTO_TCP,
      src = ip.dst,
      dst = ip.src,
      options = "",
      data = rst_obj
    })
  end
  return tostring(ip_obj)
end
local forge_icmp_reject
forge_icmp_reject = function(raw, ip)
  local original_ip_bytes = raw:sub(1, ICMP_QUOTE_MAX)
  if ip.version == 6 then
    local icmp6_body = sp(">BBH I4", ICMP6_TYPE, ICMP6_CODE, 0, 0) .. original_ip_bytes
    local icmp6_len = #icmp6_body
    local pseudo = sp(">c16 c16 I4 xxx B", ip.dst, ip.src, icmp6_len, PROTO_ICMPv6)
    local cksum = checksum(pseudo .. icmp6_body)
    icmp6_body = sp(">BBH I4", ICMP6_TYPE, ICMP6_CODE, cksum, 0) .. original_ip_bytes
    local ip_obj = new_ip({
      version = 6,
      hop_limit = 64,
      next_header = PROTO_ICMPv6,
      src = ip.dst,
      dst = ip.src,
      options = "",
      data = icmp6_body
    })
    return tostring(ip_obj)
  else
    local icmp4_body_nocsum = sp(">BBH I4", ICMP4_TYPE, ICMP4_CODE, 0, 0) .. original_ip_bytes
    local cksum = checksum(icmp4_body_nocsum)
    local icmp4_body = sp(">BBH I4", ICMP4_TYPE, ICMP4_CODE, cksum, 0) .. original_ip_bytes
    local ip_obj = new_ip({
      version = 4,
      ttl = 64,
      protocol = PROTO_ICMP,
      src = ip.dst,
      dst = ip.src,
      options = "",
      data = icmp4_body
    })
    return tostring(ip_obj)
  end
end
local handle_reject
handle_reject = function(qh_ptr, nfad, pkt_id)
  local payload_ptr = ffi.new("unsigned char*[1]")
  local payload_len = libnfq.nfq_get_payload(nfad, payload_ptr)
  if payload_len <= 0 then
    libnfq.nfq_set_verdict(qh_ptr, pkt_id, NF_DROP, 0, nil)
    return VERDICT_DONE
  end
  local raw = ffi.string(payload_ptr[0], payload_len)
  local ip, l4_off = parse_ip(raw, 1)
  if not (ip) then
    libnfq.nfq_set_verdict(qh_ptr, pkt_id, NF_DROP, 0, nil)
    return VERDICT_DONE
  end
  local proto = ip.protocol or ip.next_header
  local src_ip = ip2s(ip.src)
  local dst_ip = ip2s(ip.dst)
  local sport, dport = nil, nil
  if proto == PROTO_TCP then
    local tcp = parse_tcp(raw, l4_off)
    if tcp then
      sport, dport = tcp.spt, tcp.dpt
    end
  elseif proto == PROTO_UDP then
    local udp = parse_udp(raw, l4_off)
    if udp then
      sport, dport = udp.spt, udp.dpt
    end
  end
  local forged, response_type
  local ok, err_or_frame = pcall(function()
    if proto == PROTO_TCP then
      local tcp = parse_tcp(raw, l4_off)
      if not (tcp) then
        return nil
      end
      response_type = "rst"
      return forge_tcp_rst(ip, tcp)
    else
      response_type = "icmp"
      return forge_icmp_reject(raw, ip)
    end
  end)
  if not (ok) then
    log_warn({
      action = "forge_error",
      src = src_ip,
      dst = dst_ip,
      proto = proto,
      err = tostring(err_or_frame)
    })
    libnfq.nfq_set_verdict(qh_ptr, pkt_id, NF_DROP, 0, nil)
    return VERDICT_DONE
  end
  forged = err_or_frame
  if not (forged) then
    libnfq.nfq_set_verdict(qh_ptr, pkt_id, NF_DROP, 0, nil)
    return VERDICT_DONE
  end
  local forged_ptr = ffi.cast("const unsigned char*", forged)
  libnfq.nfq_set_verdict(qh_ptr, pkt_id, NF_ACCEPT, #forged, forged_ptr)
  log_debug({
    action = "reject_forge",
    queue = 3,
    src = src_ip,
    dst = dst_ip,
    sport = sport,
    dport = dport,
    proto = proto,
    response = response_type
  })
  return VERDICT_DONE
end
local run
run = function(queue_num, cfg)
  set_action_prefix("reject_")
  log_info({
    action = "worker_start",
    queue = queue_num
  })
  return run_queue(tonumber(queue_num), handle_reject)
end
return {
  run = run
}
