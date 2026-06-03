local new_ip, s2ip
do
  local _obj_0 = require("ipparse.l3.ip")
  new_ip, s2ip = _obj_0.new, _obj_0.s2ip
end
local new_udp
new_udp = require("ipparse.l4.udp").new
local PROTO_UDP = 17
local pick_resolver
pick_resolver = function(resolvers, version)
  local want_v6 = version == 6
  local _list_0 = (resolvers or { })
  for _index_0 = 1, #_list_0 do
    local ip = _list_0[_index_0]
    local is_v6 = ip:find(":", 1, true) and true or false
    if is_v6 == want_v6 then
      return ip
    end
  end
  return nil
end
local build_udp
build_udp = function(ip, l4, dns_raw, validator_ip)
  if not (ip and l4 and dns_raw and validator_ip) then
    return nil
  end
  if not (l4.proto == "udp") then
    return nil
  end
  local ok, dst_raw = pcall(s2ip, validator_ip)
  if not (ok and dst_raw) then
    return nil
  end
  if ip.version == 4 and #dst_raw ~= 4 then
    return nil
  end
  if ip.version == 6 and #dst_raw ~= 16 then
    return nil
  end
  local udp = new_udp({
    spt = l4.spt,
    dpt = l4.dpt,
    checksum = 0,
    data = dns_raw
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
    src = ip.src,
    dst = dst_raw,
    protocol = PROTO_UDP,
    next_header = PROTO_UDP,
    data = udp
  })
  return tostring(ip_pkt)
end
return {
  pick_resolver = pick_resolver,
  build_udp = build_udp
}
