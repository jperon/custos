local new_ip, ip_proto, s2ip
do
  local _obj_0 = require("ipparse.l3.ip")
  new_ip, ip_proto, s2ip = _obj_0.new, _obj_0.proto, _obj_0.s2ip
end
local new_udp
new_udp = require("ipparse.l4.udp").new
local new_tcp, flags
do
  local _obj_0 = require("ipparse.l4.tcp")
  new_tcp, flags = _obj_0.new, _obj_0.flags
end
local dns_mod = require("ipparse.l7.dns")
local sp
sp = require("ipparse.lib.pack_compat").pack
local encode_dns_name
encode_dns_name = require("lib.dns_name").encode_dns_name
local PROTO_UDP = ip_proto.UDP
local PROTO_TCP = ip_proto.TCP
local QTYPE_A = 1
local QTYPE_AAAA = 28
local PSH, ACK, FIN
PSH, ACK, FIN = flags.PSH, flags.ACK, flags.FIN
local wrap_ip
wrap_ip = function(ip, l4_obj, proto)
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
    protocol = proto,
    next_header = proto,
    data = l4_obj
  })
  return tostring(ip_pkt)
end
local encap
encap = function(ip, l4, dns_obj)
  if l4.proto == "tcp" then
    local dns_bytes = tostring(dns_obj)
    local data_payload = sp(">H", #dns_bytes) .. dns_bytes
    local server_seq = l4.ack_n
    local base_seq = l4.tcp_init_seq or l4.seq_n
    local client_len = l4.tcp_dns_raw and (2 + #l4.tcp_dns_raw) or 0
    local server_ack = (base_seq + client_len) % 0x100000000
    local mk
    mk = function(tcp_flags, seq, payload)
      local tcp = new_tcp({
        spt = l4.dpt,
        dpt = l4.spt,
        seq_n = seq,
        ack_n = server_ack,
        flags = tcp_flags,
        window = 65535,
        urg_ptr = 0,
        header_len = 0x50,
        options = "",
        checksum = 0,
        data = payload
      })
      return wrap_ip(ip, tcp, PROTO_TCP)
    end
    return {
      mk((PSH + ACK), server_seq, data_payload),
      mk((FIN + ACK), (server_seq + #data_payload) % 0x100000000, "")
    }
  else
    local udp = new_udp({
      spt = l4.dpt,
      dpt = l4.spt,
      checksum = 0,
      data = dns_obj
    })
    return {
      wrap_ip(ip, udp, PROTO_UDP)
    }
  end
end
local build_dns
build_dns = function(txid, q, answers)
  return dns_mod.new({
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
    answers = answers
  })
end
local forge_dns_response
forge_dns_response = function(ip, l4, txid, q, ip4_str, ip6_str)
  if not (q.qtype == QTYPE_A or q.qtype == QTYPE_AAAA) then
    return nil
  end
  local rdata
  if q.qtype == QTYPE_A and ip4_str then
    local ok, raw = pcall(s2ip, ip4_str)
    if ok and raw and #raw == 4 then
      rdata = raw
    end
  elseif q.qtype == QTYPE_AAAA and ip6_str then
    local ok, raw = pcall(s2ip, ip6_str)
    if ok and raw and #raw == 16 then
      rdata = raw
    end
  end
  local answers = rdata and {
    {
      rname = "\xC0\x0C",
      rtype = q.qtype,
      rclass = 1,
      rdata = rdata
    }
  } or { }
  return encap(ip, l4, build_dns(txid, q, answers))
end
return {
  forge_dns_response = forge_dns_response
}
