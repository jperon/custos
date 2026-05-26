package.path = "src/?.lua;src/?/init.lua;src/?/?.lua;lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path
local forge_dns = require("forge_dns")
local dns_mod = require("ipparse.l7.dns")
local parse_ip, new_ip, s2ip
do
  local _obj_0 = require("ipparse.l3.ip")
  parse_ip, new_ip, s2ip = _obj_0.parse, _obj_0.new, _obj_0.s2ip
end
local parse_udp, new_udp
do
  local _obj_0 = require("ipparse.l4.udp")
  parse_udp, new_udp = _obj_0.parse, _obj_0.new
end
return describe("forge_dns_response", function()
  return it("forges a valid IPv4 DNS answer without crashing", function()
    local ip = new_ip({
      version = 4,
      src = s2ip("192.168.1.42"),
      dst = s2ip("8.8.8.8"),
      protocol = 17,
      ttl = 64,
      data = ""
    })
    local udp = new_udp({
      spt = 53,
      dpt = 5353,
      checksum = 0,
      data = ""
    })
    local q = {
      name = "captive.example",
      qtype = dns_mod.types.A
    }
    local raw = forge_dns.forge_dns_response(ip, udp, 0x1234, q, "192.168.1.1", nil)
    assert.is_not_nil(raw)
    assert.is_true(#raw > 0)
    local parsed_ip, ip_off = parse_ip(raw, 1)
    assert.is_not_nil(parsed_ip)
    local parsed_udp, udp_off = parse_udp(raw, parsed_ip.data_off)
    assert.is_not_nil(parsed_udp)
    local parsed_dns = dns_mod.parse(raw:sub(parsed_udp.data_off), 1, false)
    assert.is_not_nil(parsed_dns)
    assert.equals(1, #parsed_dns.answers)
    return assert.equals(dns_mod.types.A, parsed_dns.answers[1].rtype)
  end)
end)
