package.path = "src/?.lua;src/?/init.lua;src/?/?.lua;lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path
local forge_dns = require("forge_dns")
local dns_mod = require("ipparse.l7.dns")
local bit = require("bit")
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
local parse_tcp, flags
do
  local _obj_0 = require("ipparse.l4.tcp")
  parse_tcp, flags = _obj_0.parse, _obj_0.flags
end
local make_ip4
make_ip4 = function()
  return new_ip({
    version = 4,
    src = s2ip("192.168.1.42"),
    dst = s2ip("8.8.8.8"),
    protocol = 17,
    ttl = 64,
    data = ""
  })
end
describe("forge_dns_response (UDP)", function()
  it("renvoie une liste d'un paquet IPv4 UDP DNS valide", function()
    local udp = {
      proto = "udp",
      spt = 53,
      dpt = 5353
    }
    local q = {
      name = "captive.example",
      qtype = dns_mod.types.A
    }
    local pkts = forge_dns.forge_dns_response(make_ip4(), udp, 0x1234, q, "192.168.1.1", nil)
    assert.is_not_nil(pkts)
    assert.equals(1, #pkts)
    local raw = pkts[1]
    local parsed_ip = parse_ip(raw, 1)
    assert.is_not_nil(parsed_ip)
    local parsed_udp = parse_udp(raw, parsed_ip.data_off)
    assert.is_not_nil(parsed_udp)
    local parsed_dns = dns_mod.parse(raw:sub(parsed_udp.data_off), 1, false)
    assert.is_not_nil(parsed_dns)
    assert.equals(1, #parsed_dns.answers)
    return assert.equals(dns_mod.types.A, parsed_dns.answers[1].rtype)
  end)
  it("ports inversés (réponse vers le client)", function()
    local udp = {
      proto = "udp",
      spt = 53,
      dpt = 5353
    }
    local q = {
      name = "captive.example",
      qtype = dns_mod.types.A
    }
    local pkts = forge_dns.forge_dns_response(make_ip4(), udp, 0x1, q, "192.168.1.1", nil)
    local parsed_ip = parse_ip(pkts[1], 1)
    local parsed_udp = parse_udp(pkts[1], parsed_ip.data_off)
    assert.equals(5353, parsed_udp.spt)
    return assert.equals(53, parsed_udp.dpt)
  end)
  it("qtype non A/AAAA → nil", function()
    local udp = {
      proto = "udp",
      spt = 53,
      dpt = 5353
    }
    local q = {
      name = "captive.example",
      qtype = dns_mod.types.TXT
    }
    return assert.is_nil(forge_dns.forge_dns_response(make_ip4(), udp, 0x1, q, "192.168.1.1", nil))
  end)
  return it("forge une réponse AAAA (IPv6) avec rdata 16 octets", function()
    local ip6 = new_ip({
      version = 6,
      src = s2ip("2001:db8::1"),
      dst = s2ip("2001:db8::53"),
      next_header = 17,
      hop_limit = 64,
      data = ""
    })
    local udp = {
      proto = "udp",
      spt = 53,
      dpt = 5353
    }
    local q = {
      name = "captive.example",
      qtype = dns_mod.types.AAAA
    }
    local pkts = forge_dns.forge_dns_response(ip6, udp, 0x1, q, nil, "fd00::1")
    assert.equals(1, #pkts)
    local parsed_ip = parse_ip(pkts[1], 1)
    local parsed_udp = parse_udp(pkts[1], parsed_ip.data_off)
    local dns = dns_mod.parse(pkts[1]:sub(parsed_udp.data_off), 1, false)
    assert.equals(1, #dns.answers)
    assert.equals(dns_mod.types.AAAA, dns.answers[1].rtype)
    return assert.equals(16, #dns.answers[1].rdata)
  end)
end)
return describe("forge_dns_response (TCP)", function()
  return it("renvoie deux segments : données PSH+ACK puis FIN+ACK", function()
    local tcp = {
      proto = "tcp",
      spt = 40000,
      dpt = 53,
      seq_n = 1000,
      ack_n = 5000,
      tcp_init_seq = 1000,
      tcp_dns_raw = ("x"):rep(20)
    }
    local q = {
      name = "captive.example",
      qtype = dns_mod.types.A
    }
    local pkts = forge_dns.forge_dns_response(make_ip4(), tcp, 0x1234, q, "192.168.1.1", nil)
    assert.is_not_nil(pkts)
    assert.equals(2, #pkts)
    local ip0 = parse_ip(pkts[1], 1)
    local t0 = parse_tcp(pkts[1], ip0.data_off)
    assert.equals((flags.PSH + flags.ACK), t0.flags)
    assert.equals(5000, t0.seq_n)
    assert.equals(1022, t0.ack_n)
    local payload = pkts[1]:sub(t0.data_off)
    local dlen = bit.bor(bit.lshift(payload:byte(1), 8), payload:byte(2))
    assert.equals(#payload - 2, dlen)
    local dns = dns_mod.parse(payload:sub(3), 1, false)
    assert.equals(1, #dns.answers)
    assert.equals(dns_mod.types.A, dns.answers[1].rtype)
    local ip1 = parse_ip(pkts[2], 1)
    local t1 = parse_tcp(pkts[2], ip1.data_off)
    assert.equals((flags.FIN + flags.ACK), t1.flags)
    return assert.equals((5000 + #payload), t1.seq_n)
  end)
end)
