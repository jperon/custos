local parse_ip4
parse_ip4 = require("ipparse.l3.ip4").parse
local parse_ip6
parse_ip6 = require("ipparse.l3.ip6").parse
local parse_udp
parse_udp = require("ipparse.l4.udp").parse
local parse_tcp
parse_tcp = require("ipparse.l4.tcp").parse
local parse_dns, types
do
  local _obj_0 = require("ipparse.l7.dns")
  parse_dns, types = _obj_0.parse, _obj_0.types
end
local ipparse_ip2s
ipparse_ip2s = require("ipparse.l3.ip").ip2s
local IP2S_CACHE_MAX = 512
local _ip4s_cache = { }
local _ip4s_n = 0
local ip2s
ip2s = function(raw)
  if not (raw) then
    return nil
  end
  if not (#raw == 4) then
    return ipparse_ip2s(raw)
  end
  local hit = _ip4s_cache[raw]
  if hit then
    return hit
  end
  local s = ipparse_ip2s(raw)
  if _ip4s_n >= IP2S_CACHE_MAX then
    _ip4s_cache = { }
    _ip4s_n = 0
  end
  _ip4s_cache[raw] = s
  _ip4s_n = _ip4s_n + 1
  return s
end
return {
  parse_ip4 = parse_ip4,
  parse_ip6 = parse_ip6,
  parse_udp = parse_udp,
  parse_tcp = parse_tcp,
  parse_dns = parse_dns,
  ip2s = ip2s,
  dns_types = types
}
