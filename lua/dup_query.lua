local new_ip, s2ip
do
  local _obj_0 = require("ipparse.l3.ip")
  new_ip, s2ip = _obj_0.new, _obj_0.s2ip
end
local new_udp
new_udp = require("ipparse.l4.udp").new
local PROTO_UDP = 17
local _pickers = setmetatable({ }, {
  __mode = "k"
})
local EMPTY = { }
local udp_lists
udp_lists = function(resolvers)
  local lists = {
    v4 = { },
    v6 = { }
  }
  local _list_0 = (resolvers or { })
  for _index_0 = 1, #_list_0 do
    local _continue_0 = false
    repeat
      local ip = _list_0[_index_0]
      if not (type(ip) == "string") then
        _continue_0 = true
        break
      end
      if ip:find("://", 1, true) then
        _continue_0 = true
        break
      end
      if ip:find(":", 1, true) then
        lists.v6[#lists.v6 + 1] = ip
      else
        lists.v4[#lists.v4 + 1] = ip
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  return lists
end
local new_picker
new_picker = function(resolvers)
  local lists = udp_lists(resolvers)
  return function(version, dns_id, sport)
    local list
    if version == 6 then
      list = lists.v6
    else
      list = lists.v4
    end
    local n = #list
    if n == 0 then
      return nil
    end
    return list[((dns_id or 0) + (sport or 0)) % n + 1]
  end
end
local get_picker
get_picker = function(resolvers)
  if not (resolvers) then
    resolvers = EMPTY
  end
  local p = _pickers[resolvers]
  if p then
    return p
  end
  p = new_picker(resolvers)
  _pickers[resolvers] = p
  return p
end
local pick_resolver
pick_resolver = function(resolvers, version)
  local pick = get_picker(resolvers)
  return pick(version, 0, 0)
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
    traffic_class = ip.traffic_class,
    flow_label = ip.flow_label,
    hop_limit = ip.hop_limit,
    src = ip.src,
    dst = dst_raw,
    protocol = PROTO_UDP,
    next_header = PROTO_UDP,
    data = udp
  })
  return tostring(ip_pkt)
end
local build_query
build_query = function(ip, l4, query_raw)
  if not (ip and l4 and query_raw) then
    return nil
  end
  if not (l4.proto == "udp") then
    return nil
  end
  local udp = new_udp({
    spt = l4.dpt,
    dpt = l4.spt,
    checksum = 0,
    data = query_raw
  })
  local ip_pkt = new_ip({
    version = ip.version,
    v_ihl = ip.v_ihl,
    tos = ip.tos,
    id = ip.id,
    ff = ip.ff,
    ttl = 64,
    options = ip.options or "",
    traffic_class = ip.traffic_class,
    flow_label = ip.flow_label,
    hop_limit = 64,
    src = ip.dst,
    dst = ip.src,
    protocol = PROTO_UDP,
    next_header = PROTO_UDP,
    data = udp
  })
  return tostring(ip_pkt)
end
return {
  pick_resolver = pick_resolver,
  new_picker = new_picker,
  get_picker = get_picker,
  build_udp = build_udp,
  build_query = build_query
}
