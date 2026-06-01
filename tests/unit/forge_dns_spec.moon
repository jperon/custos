-- tests/unit/forge_dns_spec.moon
-- Regression tests for captive DNS forging (UDP + TCP).

package.path = "src/?.lua;src/?/init.lua;src/?/?.lua;lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path

forge_dns = require "forge_dns"
dns_mod = require "ipparse.l7.dns"
bit = require "bit"

{ parse: parse_ip, new: new_ip, :s2ip } = require "ipparse.l3.ip"
{ parse: parse_udp, new: new_udp } = require "ipparse.l4.udp"
{ parse: parse_tcp, :flags } = require "ipparse.l4.tcp"

make_ip4 = -> new_ip {
  version: 4, src: s2ip("192.168.1.42"), dst: s2ip("8.8.8.8")
  protocol: 17, ttl: 64, data: ""
}

describe "forge_dns_response (UDP)", ->

  it "renvoie une liste d'un paquet IPv4 UDP DNS valide", ->
    udp = { proto: "udp", spt: 53, dpt: 5353 }
    q = { name: "captive.example", qtype: dns_mod.types.A }

    pkts = forge_dns.forge_dns_response make_ip4!, udp, 0x1234, q, "192.168.1.1", nil
    assert.is_not_nil pkts
    assert.equals 1, #pkts

    raw = pkts[1]
    parsed_ip = parse_ip raw, 1
    assert.is_not_nil parsed_ip
    parsed_udp = parse_udp raw, parsed_ip.data_off
    assert.is_not_nil parsed_udp
    parsed_dns = dns_mod.parse raw\sub(parsed_udp.data_off), 1, false
    assert.is_not_nil parsed_dns
    assert.equals 1, #parsed_dns.answers
    assert.equals dns_mod.types.A, parsed_dns.answers[1].rtype

  it "ports inversés (réponse vers le client)", ->
    udp = { proto: "udp", spt: 53, dpt: 5353 }
    q = { name: "captive.example", qtype: dns_mod.types.A }
    pkts = forge_dns.forge_dns_response make_ip4!, udp, 0x1, q, "192.168.1.1", nil
    parsed_ip = parse_ip pkts[1], 1
    parsed_udp = parse_udp pkts[1], parsed_ip.data_off
    assert.equals 5353, parsed_udp.spt
    assert.equals 53, parsed_udp.dpt

  it "qtype non A/AAAA → nil", ->
    udp = { proto: "udp", spt: 53, dpt: 5353 }
    q = { name: "captive.example", qtype: dns_mod.types.TXT }
    assert.is_nil forge_dns.forge_dns_response make_ip4!, udp, 0x1, q, "192.168.1.1", nil

  it "forge une réponse AAAA (IPv6) avec rdata 16 octets", ->
    ip6 = new_ip { version: 6, src: s2ip("2001:db8::1"), dst: s2ip("2001:db8::53"), next_header: 17, hop_limit: 64, data: "" }
    udp = { proto: "udp", spt: 53, dpt: 5353 }
    q = { name: "captive.example", qtype: dns_mod.types.AAAA }
    pkts = forge_dns.forge_dns_response ip6, udp, 0x1, q, nil, "fd00::1"
    assert.equals 1, #pkts
    parsed_ip = parse_ip pkts[1], 1
    parsed_udp = parse_udp pkts[1], parsed_ip.data_off
    dns = dns_mod.parse pkts[1]\sub(parsed_udp.data_off), 1, false
    assert.equals 1, #dns.answers
    assert.equals dns_mod.types.AAAA, dns.answers[1].rtype
    assert.equals 16, #dns.answers[1].rdata

describe "forge_dns_response (TCP)", ->

  it "renvoie deux segments : données PSH+ACK puis FIN+ACK", ->
    tcp = {
      proto: "tcp", spt: 40000, dpt: 53
      seq_n: 1000, ack_n: 5000
      tcp_init_seq: 1000, tcp_dns_raw: ("x")\rep(20)
    }
    q = { name: "captive.example", qtype: dns_mod.types.A }
    pkts = forge_dns.forge_dns_response make_ip4!, tcp, 0x1234, q, "192.168.1.1", nil
    assert.is_not_nil pkts
    assert.equals 2, #pkts

    -- Segment données
    ip0 = parse_ip pkts[1], 1
    t0  = parse_tcp pkts[1], ip0.data_off
    assert.equals (flags.PSH + flags.ACK), t0.flags
    assert.equals 5000, t0.seq_n                       -- = ack_n client
    assert.equals 1022, t0.ack_n                       -- init_seq + 2 + 20

    -- Préfixe de longueur DNS-over-TCP + parse
    payload = pkts[1]\sub t0.data_off
    dlen = bit.bor bit.lshift(payload\byte(1), 8), payload\byte(2)
    assert.equals #payload - 2, dlen
    dns = dns_mod.parse payload\sub(3), 1, false
    assert.equals 1, #dns.answers
    assert.equals dns_mod.types.A, dns.answers[1].rtype

    -- Segment FIN+ACK (sans données), seq = seq données + longueur du payload
    ip1 = parse_ip pkts[2], 1
    t1  = parse_tcp pkts[2], ip1.data_off
    assert.equals (flags.FIN + flags.ACK), t1.flags
    assert.equals (5000 + #payload), t1.seq_n
