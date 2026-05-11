local new_ip, ip_proto, s2ip
do
  local _obj_0 = require("ipparse.l3.ip")
  new_ip, ip_proto, s2ip = _obj_0.new, _obj_0.proto, _obj_0.s2ip
end
local new_udp
new_udp = require("ipparse.l4.udp").new
local sp
sp = require("ipparse.lib.pack_compat").pack
local PROTO_UDP = ip_proto.UDP
local QTYPE_A = 1
local QTYPE_AAAA = 28
local encode_dns_name
encode_dns_name = function(name)
  name = name:gsub("%.+$", "")
  local parts = { }
  for label in name:gmatch("[^.]+") do
    parts[#parts + 1] = string.char(#label) .. label
  end
  return table.concat(parts) .. "\x00"
end
local forge_dns_response
forge_dns_response = function(pkt, q, ip4_str, ip6_str)
  if not (q.qtype == QTYPE_A or q.qtype == QTYPE_AAAA) then
    return nil
  end
  if pkt.l4.proto ~= "udp" then
    return nil
  end
  local rdata
  local ancount = 0
  if q.qtype == QTYPE_A and ip4_str then
    local ok, raw = pcall(s2ip, ip4_str)
    if ok and raw and #raw == 4 then
      rdata = raw
      ancount = 1
    end
  elseif q.qtype == QTYPE_AAAA and ip6_str then
    local ok, raw = pcall(s2ip, ip6_str)
    if ok and raw and #raw == 16 then
      rdata = raw
      ancount = 1
    end
  end
  local dns_hdr = sp(">H BB HHHH", pkt.dns.txid, 0x84, 0x00, 1, ancount, 0, 0)
  local question = encode_dns_name(q.qname) .. sp(">HH", q.qtype, 1)
  local answer
  if ancount == 1 then
    answer = "\xC0\x0C" .. sp(">HH I4 s2", q.qtype, 1, 60, rdata)
  else
    answer = ""
  end
  local dns_payload = dns_hdr .. question .. answer
  local udp_obj = new_udp({
    spt = pkt.l4.dst_port,
    dpt = pkt.l4.src_port,
    checksum = 0,
    data = dns_payload
  })
  local ip_obj
  if pkt.ip.version == 6 then
    ip_obj = new_ip({
      version = 6,
      hop_limit = 64,
      next_header = PROTO_UDP,
      src = pkt.ip.dst_ip_raw,
      dst = pkt.ip.src_ip_raw,
      data = udp_obj
    })
  else
    ip_obj = new_ip({
      version = 4,
      ttl = 64,
      protocol = PROTO_UDP,
      src = pkt.ip.dst_ip_raw,
      dst = pkt.ip.src_ip_raw,
      options = "",
      data = udp_obj
    })
  end
  return tostring(ip_obj)
end
return {
  forge_dns_response = forge_dns_response
}
