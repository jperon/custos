local new_ip, ip_proto, s2ip
do
  local _obj_0 = require("ipparse.l3.ip")
  new_ip, ip_proto, s2ip = _obj_0.new, _obj_0.proto, _obj_0.s2ip
end
local new_udp
new_udp = require("ipparse.l4.udp").new
local dns_mod = require("ipparse.l7.dns")
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
forge_dns_response = function(ip, udp, txid, q, ip4_str, ip6_str)
  if not (q.qtype == QTYPE_A or q.qtype == QTYPE_AAAA) then
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
  local dns_obj = dns_mod.new({
    header = dns_mod.new_header({
      id = txid,
      qr = true,
      aa = true
    }),
    questions = {
      {
        qname = encode_dns_name(q.name),
        qtype = q.qtype,
        qclass = 1
      }
    },
    answers = ancount == 1 and {
      {
        rname = "\xC0\x0C",
        rtype = q.qtype,
        rclass = 1,
        rdata = rdata
      }
    } or { }
  })
  local l4 = new_udp({
    spt = udp.dpt,
    dpt = udp.spt,
    checksum = 0,
    data = dns_obj
  })
  local ip_pkt = new_ip({
    version = ip.version,
    v_ihl = ip.v_ihl,
    tos = ip.tos,
    id = ip.id,
    ff = ip.ff,
    ttl = ip.ttl,
    options = ip.options or "",
    vtf = ip.vtf,
    hop_limit = ip.hop_limit,
    src = ip.dst,
    dst = ip.src,
    protocol = PROTO_UDP,
    next_header = PROTO_UDP,
    data = l4
  })
  return tostring(ip_pkt)
end
return {
  forge_dns_response = forge_dns_response
}
