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
local ip2s
ip2s = require("ipparse.l3.ip").ip2s
return {
  parse_ip4 = parse_ip4,
  parse_ip6 = parse_ip6,
  parse_udp = parse_udp,
  parse_tcp = parse_tcp,
  parse_dns = parse_dns,
  ip2s = ip2s,
  dns_types = types
}
