-- tests/unit/forge_dns_spec.moon
-- Regression tests for captive DNS forging.

package.path = "src/?.lua;src/?/init.lua;src/?/?.lua;lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path

forge_dns = require "forge_dns"
dns_mod = require "ipparse.l7.dns"

{ parse: parse_ip, new: new_ip, :s2ip } = require "ipparse.l3.ip"
{ parse: parse_udp, new: new_udp } = require "ipparse.l4.udp"

describe "forge_dns_response", ->

  it "forges a valid IPv4 DNS answer without crashing", ->
    ip = new_ip {
      version: 4
      src: s2ip "192.168.1.42"
      dst: s2ip "8.8.8.8"
      protocol: 17
      ttl: 64
      data: ""
    }

    udp = new_udp {
      spt: 53
      dpt: 5353
      checksum: 0
      data: ""
    }

    q = {
      name: "captive.example"
      qtype: dns_mod.types.A
    }

    raw = forge_dns.forge_dns_response ip, udp, 0x1234, q, "192.168.1.1", nil
    assert.is_not_nil raw
    assert.is_true #raw > 0

    parsed_ip, ip_off = parse_ip raw, 1
    assert.is_not_nil parsed_ip
    parsed_udp, udp_off = parse_udp raw, parsed_ip.data_off
    assert.is_not_nil parsed_udp
    parsed_dns = dns_mod.parse raw\sub(parsed_udp.data_off), 1, false
    assert.is_not_nil parsed_dns
    assert.equals 1, #parsed_dns.answers
    assert.equals dns_mod.types.A, parsed_dns.answers[1].rtype
