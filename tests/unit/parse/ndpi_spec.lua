local bit = require("bit")
local ffi = require("ffi")
package.loaded["ffi_ndpi"] = {
  ffi = ffi,
  ndpi_lib = { },
  major = 4
}
package.loaded["parse.ndpi_v4"] = {
  init = function()
    return nil
  end,
  detect = function()
    return 0, 0
  end,
  cleanup = function()
    return nil
  end
}
package.loaded["parse.ndpi_v5"] = {
  init = function()
    return nil
  end,
  detect = function()
    return 0, 0
  end,
  cleanup = function()
    return nil
  end
}
local m_ndpi = dofile("lua/parse/ndpi.lua")
local parse_packet = m_ndpi.parse_packet
local patch_and_checksum = m_ndpi.patch_and_checksum
local extract_dns_payload = m_ndpi.extract_dns_payload
local patch_ttl_in_dns = m_ndpi.patch_ttl_in_dns
local replace_dns_payload = m_ndpi.replace_dns_payload
local make_dns
make_dns = function(qname_encoded, qtype, is_response, txid)
  txid = txid or 0x1234
  qtype = qtype or 1
  local flags_hi = is_response and 0x81 or 0x01
  local flags_lo = 0x00
  local hdr = string.char(bit.rshift(bit.band(txid, 0xFF00), 8), bit.band(txid, 0xFF), flags_hi, flags_lo, 0, 1, 0, 0, 0, 0, 0, 0)
  local qsection = qname_encoded .. string.char(0, qtype, 0, 1)
  return hdr .. qsection
end
local make_ipv4_udp_dns
make_ipv4_udp_dns = function(src_ip, dst_ip, src_port, dst_port, dns_payload)
  local total_len = 20 + 8 + #dns_payload
  local ihl_ver = 0x45
  local ip4bytes
  ip4bytes = function(s)
    local a, b, c, d = s:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
    return string.char(tonumber(a), tonumber(b), tonumber(c), tonumber(d))
  end
  local ip = string.char(ihl_ver, 0, bit.rshift(bit.band(total_len, 0xFF00), 8), bit.band(total_len, 0xFF), 0, 1, 0, 0, 64, 17, 0, 0)
  ip = ip .. ip4bytes(src_ip) .. ip4bytes(dst_ip)
  local udp_len = 8 + #dns_payload
  local udp = string.char(bit.rshift(bit.band(src_port, 0xFF00), 8), bit.band(src_port, 0xFF), bit.rshift(bit.band(dst_port, 0xFF00), 8), bit.band(dst_port, 0xFF), bit.rshift(bit.band(udp_len, 0xFF00), 8), bit.band(udp_len, 0xFF), 0, 0)
  return ip .. udp .. dns_payload
end
local make_ipv4_tcp_dns
make_ipv4_tcp_dns = function(src_ip, dst_ip, src_port, dst_port, dns_payload)
  local dns_len = #dns_payload
  local pfx = string.char(bit.rshift(bit.band(dns_len, 0xFF00), 8), bit.band(dns_len, 0xFF))
  local tcp_payload = pfx .. dns_payload
  local total_len = 20 + 20 + #tcp_payload
  local ip4bytes
  ip4bytes = function(s)
    local a, b, c, d = s:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
    return string.char(tonumber(a), tonumber(b), tonumber(c), tonumber(d))
  end
  local ip = string.char(0x45, 0, bit.rshift(bit.band(total_len, 0xFF00), 8), bit.band(total_len, 0xFF), 0, 1, 0, 0, 64, 6, 0, 0)
  ip = ip .. ip4bytes(src_ip) .. ip4bytes(dst_ip)
  local tcp = string.char(bit.rshift(bit.band(src_port, 0xFF00), 8), bit.band(src_port, 0xFF), bit.rshift(bit.band(dst_port, 0xFF00), 8), bit.band(dst_port, 0xFF), 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0x72, 0x10, 0, 0, 0, 0)
  return ip .. tcp .. tcp_payload
end
local make_ipv6_udp_dns
make_ipv6_udp_dns = function(src_ip6, dst_ip6, src_port, dst_port, dns_payload)
  local udp_len = 8 + #dns_payload
  local pay_len = udp_len
  local ip6 = string.char(0x60, 0, 0, 0, bit.rshift(bit.band(pay_len, 0xFF00), 8), bit.band(pay_len, 0xFF), 17, 64) .. src_ip6 .. dst_ip6
  local udp = string.char(bit.rshift(bit.band(src_port, 0xFF00), 8), bit.band(src_port, 0xFF), bit.rshift(bit.band(dst_port, 0xFF00), 8), bit.band(dst_port, 0xFF), bit.rshift(bit.band(udp_len, 0xFF00), 8), bit.band(udp_len, 0xFF), 0, 0)
  return ip6 .. udp .. dns_payload
end
local make_ipv6_ext_udp_dns
make_ipv6_ext_udp_dns = function(src_ip6, dst_ip6, src_port, dst_port, dns_payload, first_nh, ext_raw)
  local udp_len = 8 + #dns_payload
  local pay_len = #ext_raw + udp_len
  local ip6 = string.char(0x60, 0, 0, 0, bit.rshift(bit.band(pay_len, 0xFF00), 8), bit.band(pay_len, 0xFF), first_nh, 64) .. src_ip6 .. dst_ip6
  local udp = string.char(bit.rshift(bit.band(src_port, 0xFF00), 8), bit.band(src_port, 0xFF), bit.rshift(bit.band(dst_port, 0xFF00), 8), bit.band(dst_port, 0xFF), bit.rshift(bit.band(udp_len, 0xFF00), 8), bit.band(udp_len, 0xFF), 0, 0)
  return ip6 .. ext_raw .. udp .. dns_payload
end
local make_tcp_raw
make_tcp_raw = function(src_ip, dst_ip, src_port, dst_port, tcp_seq, tcp_payload)
  local total_len = 20 + 20 + #tcp_payload
  local ip4b
  ip4b = function(s)
    local a, b, c, d = s:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
    return string.char(tonumber(a), tonumber(b), tonumber(c), tonumber(d))
  end
  local ip = string.char(0x45, 0, bit.rshift(bit.band(total_len, 0xFF00), 8), bit.band(total_len, 0xFF), 0, 1, 0, 0, 64, 6, 0, 0) .. ip4b(src_ip) .. ip4b(dst_ip)
  local tcp = string.char(bit.rshift(bit.band(src_port, 0xFF00), 8), bit.band(src_port, 0xFF), bit.rshift(bit.band(dst_port, 0xFF00), 8), bit.band(dst_port, 0xFF), bit.rshift(bit.band(tcp_seq, 0xFF000000), 24), bit.rshift(bit.band(tcp_seq, 0x00FF0000), 16), bit.rshift(bit.band(tcp_seq, 0x0000FF00), 8), bit.band(tcp_seq, 0xFF), 0, 0, 0, 0, 0x50, 0x18, 0x72, 0x10, 0, 0, 0, 0)
  return ip .. tcp .. tcp_payload
end
describe("parse/ndpi", function()
  describe("parse_packet", function()
    it("UDP DNS minimal", function()
      local dns = make_dns("\3www\6github\3com\0", 1, false)
      local raw = make_ipv4_udp_dns("192.168.1.42", "8.8.8.8", 54321, 53, dns)
      local pkt = parse_packet(raw)
      assert.is_not_nil(pkt, "parse_packet ne doit pas retourner nil")
      assert.equals("udp", pkt.l4.proto)
      assert.equals(0x1234, pkt.dns.txid)
      return assert.equals("www.github.com", pkt.questions[1].qname)
    end)
    it("TCP DNS minimal", function()
      local dns = make_dns("\3www\6github\3com\0", 1, false)
      local raw = make_ipv4_tcp_dns("192.168.1.42", "8.8.8.8", 54321, 53, dns)
      local pkt = parse_packet(raw)
      assert.is_not_nil(pkt, "parse_packet ne doit pas retourner nil")
      assert.equals("tcp", pkt.l4.proto)
      assert.equals(0x1234, pkt.dns.txid)
      return assert.equals("www.github.com", pkt.questions[1].qname)
    end)
    it("TCP DNS too short (no length prefix)", function()
      local raw = make_ipv4_tcp_dns("192.168.1.42", "8.8.8.8", 54322, 53, "")
      raw = raw:sub(1, #raw - 1)
      local pkt = parse_packet(raw)
      return assert.is_nil(pkt, "doit retourner nil si payload TCP < 14 B")
    end)
    it("IPv6 + Hop-by-Hop (type 0) + UDP DNS", function()
      local hbh = string.char(17, 0, 0, 0, 0, 0, 0, 0)
      local dns = make_dns("\3www\6github\3com\0", 1, false)
      local src6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x42"
      local dst6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x01"
      local raw = make_ipv6_ext_udp_dns(src6, dst6, 54321, 53, dns, 0, hbh)
      local pkt = parse_packet(raw)
      assert.is_not_nil(pkt, "parse_packet nil avec Hop-by-Hop")
      assert.equals(6, pkt.ip.version)
      assert.equals(48, pkt.ip.ihl)
      assert.equals("udp", pkt.l4.proto)
      assert.equals(0x1234, pkt.dns.txid)
      return assert.equals("www.github.com", pkt.questions[1].qname)
    end)
    it("IPv6 + Routing (type 43) + UDP DNS", function()
      local rh = string.char(17, 0, 0, 0, 0, 0, 0, 0)
      local dns = make_dns("\3www\6github\3com\0", 1, false)
      local src6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x42"
      local dst6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x01"
      local raw = make_ipv6_ext_udp_dns(src6, dst6, 54321, 53, dns, 43, rh)
      local pkt = parse_packet(raw)
      assert.is_not_nil(pkt, "parse_packet nil avec Routing header")
      assert.equals(48, pkt.ip.ihl)
      assert.equals("udp", pkt.l4.proto)
      return assert.equals("www.github.com", pkt.questions[1].qname)
    end)
    it("IPv6 + Fragment (type 44) + UDP DNS", function()
      local fh = string.char(17, 0, 0, 0, 0, 0, 0, 1)
      local dns = make_dns("\3www\6github\3com\0", 1, false)
      local src6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x42"
      local dst6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x01"
      local raw = make_ipv6_ext_udp_dns(src6, dst6, 54321, 53, dns, 44, fh)
      local pkt = parse_packet(raw)
      assert.is_not_nil(pkt, "parse_packet nil avec Fragment header")
      assert.equals(48, pkt.ip.ihl)
      assert.equals("udp", pkt.l4.proto)
      return assert.equals("www.github.com", pkt.questions[1].qname)
    end)
    return it("IPv6 + Hop-by-Hop + Routing (chained) + UDP DNS", function()
      local hbh = string.char(43, 0, 0, 0, 0, 0, 0, 0)
      local rh = string.char(17, 0, 0, 0, 0, 0, 0, 0)
      local dns = make_dns("\3www\6github\3com\0", 1, false)
      local src6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x42"
      local dst6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x01"
      local raw = make_ipv6_ext_udp_dns(src6, dst6, 54321, 53, dns, 0, hbh .. rh)
      local pkt = parse_packet(raw)
      assert.is_not_nil(pkt, "parse_packet nil avec ext headers chaînés")
      assert.equals(56, pkt.ip.ihl)
      assert.equals("udp", pkt.l4.proto)
      return assert.equals("www.github.com", pkt.questions[1].qname)
    end)
  end)
  describe("patch_and_checksum", function()
    it("TCP response", function()
      local qname_enc = "\6github\3com\0"
      local txid = 0x5678
      local hdr = string.char(0x56, 0x78, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0)
      local question = qname_enc .. string.char(0, 1, 0, 1)
      local rr = "\xC0\x0C" .. string.char(0, 1, 0, 1) .. string.char(0, 0, 1, 0x2C) .. string.char(0, 4) .. string.char(1, 2, 3, 4)
      local dns_payload = hdr .. question .. rr
      local raw = make_ipv4_tcp_dns("192.168.1.42", "8.8.8.8", 54323, 53, dns_payload)
      local pkt = parse_packet(raw)
      assert.is_not_nil(pkt, "parse_packet retourne nil")
      local answers = m_ndpi.parse_answers(raw, pkt)
      local patched = patch_and_checksum(raw, pkt, answers, 60)
      assert.is_not_nil(patched, "patch_and_checksum retourne nil")
      local ttl_offset = 20 + 20 + 2 + 12 + 16 + 6 + 3
      return assert.equals(60, patched:byte(ttl_offset + 1), "TTL patché à 60")
    end)
    it("TCP 2-segment reassembly patches TTL", function()
      local qname_enc = "\6github\3com\0"
      local hdr = string.char(0x9A, 0xBC, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0)
      local question = qname_enc .. string.char(0, 1, 0, 1)
      local rr = "\xC0\x0C" .. string.char(0, 1, 0, 1) .. string.char(0, 0, 1, 0x2C) .. string.char(0, 4) .. string.char(5, 6, 7, 8)
      local dns_payload = hdr .. question .. rr
      local dns_len = #dns_payload
      local src_ip, dst_ip, src_port, dst_port = "192.168.1.42", "8.8.8.8", 54324, 53
      local init_seq = 0x00ABCDEF
      local prefix = string.char(bit.rshift(bit.band(dns_len, 0xFF00), 8), bit.band(dns_len, 0xFF))
      local raw1 = make_tcp_raw(src_ip, dst_ip, src_port, dst_port, init_seq, prefix)
      local pkt1, status1 = parse_packet(raw1)
      assert.is_nil(pkt1, "seg1 doit retourner nil (incomplet)")
      assert.equals("buffering", status1, "seg1 doit signaler buffering")
      local raw2 = make_tcp_raw(src_ip, dst_ip, src_port, dst_port, init_seq + 2, dns_payload)
      local pkt2 = (parse_packet(raw2))
      assert.is_not_nil(pkt2, "seg2 doit compléter le message DNS")
      assert.equals("tcp", pkt2.l4.proto)
      assert.equals(0x9ABC, pkt2.dns.txid)
      assert.equals(false, pkt2.tcp_single_segment)
      assert.is_not_nil(pkt2.tcp_init_seq, "tcp_init_seq doit être défini")
      assert.equals(init_seq, pkt2.tcp_init_seq)
      local answers2 = m_ndpi.parse_answers(raw2, pkt2)
      assert.equals(1, #answers2, "1 réponse attendue")
      local patched2 = patch_and_checksum(raw2, pkt2, answers2, 60)
      local expected_len = 20 + 20 + 2 + dns_len
      assert.equals(expected_len, #patched2, "taille du paquet coalesced")
      local ttl_off2 = 20 + 20 + 2 + 12 + 16 + 6 + 3
      assert.equals(60, patched2:byte(ttl_off2 + 1), "TTL patché à 60 dans paquet coalesced")
      local seq_b0 = patched2:byte(20 + 4 + 1)
      local seq_b1 = patched2:byte(20 + 4 + 2)
      local seq_b2 = patched2:byte(20 + 4 + 3)
      local seq_b3 = patched2:byte(20 + 4 + 4)
      local got_seq = bit.bor(bit.lshift(seq_b0, 24), bit.lshift(seq_b1, 16), bit.lshift(seq_b2, 8), seq_b3)
      return assert.equals(init_seq, got_seq, "champ seq TCP restauré à init_seq")
    end)
    return it("TCP 2-segment CNAME+A patches all TTLs", function()
      local qname_enc = "\6github\3com\0"
      local hdr = string.char(0xBB, 0xCC, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0)
      local question = qname_enc .. string.char(0, 1, 0, 1)
      local cname_target = "\3www\6github\3com\0"
      local rr1 = "\xC0\x0C" .. string.char(0, 5, 0, 1) .. string.char(0, 0, 1, 0x2C) .. string.char(0, 16) .. cname_target
      local rr2 = "\xC0\x0C" .. string.char(0, 1, 0, 1) .. string.char(0, 0, 1, 0x2C) .. string.char(0, 4) .. string.char(1, 2, 3, 4)
      local dns_payload = hdr .. question .. rr1 .. rr2
      local dns_len = #dns_payload
      assert.equals(72, dns_len, "dns_payload doit faire 72 B")
      local src_ip, dst_ip, src_port, dst_port = "192.168.1.42", "8.8.8.8", 54325, 53
      local init_seq2 = 0x00112233
      local prefix = string.char(bit.rshift(bit.band(dns_len, 0xFF00), 8), bit.band(dns_len, 0xFF))
      local raw1 = make_tcp_raw(src_ip, dst_ip, src_port, dst_port, init_seq2, prefix)
      local p1, s1 = parse_packet(raw1)
      assert.is_nil(p1, "seg1 nil")
      assert.equals("buffering", s1, "seg1 buffering")
      local raw2 = make_tcp_raw(src_ip, dst_ip, src_port, dst_port, init_seq2 + 2, dns_payload)
      local pkt3 = (parse_packet(raw2))
      assert.is_not_nil(pkt3, "seg2 doit compléter le message DNS")
      assert.equals(0xBBCC, pkt3.dns.txid)
      assert.equals(false, pkt3.tcp_single_segment)
      local ans3 = m_ndpi.parse_answers(raw2, pkt3)
      assert.equals(2, #ans3, "2 réponses (CNAME + A)")
      assert.equals(300, ans3[1].ttl, "RR1 TTL original = 300")
      assert.equals(300, ans3[2].ttl, "RR2 TTL original = 300")
      local patched3 = patch_and_checksum(raw2, pkt3, ans3, 42)
      local base = 42
      assert.equals(42, patched3:byte(base + 34 + 3 + 1), "RR1 (CNAME) TTL patché à 42")
      assert.equals(42, patched3:byte(base + 62 + 3 + 1), "RR2 (A) TTL patché à 42")
      assert.equals(0, patched3:byte(base + 34 + 0 + 1), "RR1 TTL byte0 = 0")
      assert.equals(0, patched3:byte(base + 34 + 1 + 1), "RR1 TTL byte1 = 0")
      assert.equals(0, patched3:byte(base + 34 + 2 + 1), "RR1 TTL byte2 = 0")
      assert.equals(0, patched3:byte(base + 62 + 0 + 1), "RR2 TTL byte0 = 0")
      assert.equals(0, patched3:byte(base + 62 + 1 + 1), "RR2 TTL byte1 = 0")
      return assert.equals(0, patched3:byte(base + 62 + 2 + 1), "RR2 TTL byte2 = 0")
    end)
  end)
  return describe("helpers ndpi", function()
    it("extract_dns_payload — UDP : retourne la sous-chaîne DNS", function()
      local dns = make_dns("\x06github\x03com\x00", 1, false, 0xABCD)
      local raw = make_ipv4_udp_dns("192.168.1.2", "8.8.8.8", 54321, 53, dns)
      local pkt = {
        ip = {
          version = 4,
          ihl = 20
        },
        l4 = {
          proto = "udp",
          off = 28,
          payload_len = #dns
        }
      }
      local result = extract_dns_payload(raw, pkt)
      return assert.equals(dns, result, "payload DNS extrait correctement")
    end)
    it("extract_dns_payload — TCP : retourne pkt.tcp_dns_raw", function()
      local dns = make_dns("\x03foo\x03com\x00", 1, false, 0x4321)
      local pkt = {
        l4 = {
          proto = "tcp"
        },
        tcp_dns_raw = dns
      }
      local result = extract_dns_payload("ignored", pkt)
      return assert.equals(dns, result, "retourne pkt.tcp_dns_raw")
    end)
    it("patch_ttl_in_dns — réécrit TTL à l'offset 0-based correct, class intact", function()
      local qname_enc = "\x06github\x03com\x00"
      local hdr = string.char(0x56, 0x78, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0)
      local question = qname_enc .. string.char(0, 1, 0, 1)
      local rr = "\xC0\x0C" .. string.char(0, 1, 0, 1) .. string.char(0, 0, 1, 0x2C) .. string.char(0, 4) .. string.char(1, 2, 3, 4)
      local dns_str = hdr .. question .. rr
      local ttl_off = 34
      local result = patch_ttl_in_dns(dns_str, {
        {
          ttl_offset = ttl_off
        }
      }, 60)
      assert.is_not_nil(result, "patch_ttl_in_dns ne doit pas retourner nil")
      assert.equals(#dns_str, #result, "longueur inchangée")
      assert.equals(0x00, result:byte(33), "CLASS hi non corrompu")
      assert.equals(0x01, result:byte(34), "CLASS lo = IN (1) non corrompu")
      assert.equals(0x00, result:byte(35), "TTL byte 0 = 0x00")
      assert.equals(0x00, result:byte(36), "TTL byte 1 = 0x00")
      assert.equals(0x00, result:byte(37), "TTL byte 2 = 0x00")
      return assert.equals(60, result:byte(38), "TTL byte 3 = 60")
    end)
    it("patch_ttl_in_dns — answers vide → payload inchangé", function()
      local dns_str = make_dns("\x03foo\x03com\x00", 1, false, 0x1111)
      local result = patch_ttl_in_dns(dns_str, { }, 60)
      assert.is_not_nil(result, "retourne non-nil même sans answers")
      return assert.equals(dns_str, result, "payload inchangé si answers vide")
    end)
    it("replace_dns_payload — IPv4 UDP : longueurs IP et UDP mises à jour", function()
      local dns_orig = make_dns("\x06github\x03com\x00", 1, false, 0xABCD)
      local raw = make_ipv4_udp_dns("8.8.8.8", "192.168.1.42", 53, 54321, dns_orig)
      local pkt = {
        ip = {
          version = 4,
          ihl = 20
        },
        l4 = {
          proto = "udp",
          off = 28,
          payload_len = #dns_orig
        }
      }
      local new_dns = dns_orig .. "\x00\x00\x00\x00"
      local result = replace_dns_payload(raw, pkt, new_dns)
      assert.is_not_nil(result, "replace_dns_payload ne doit pas retourner nil")
      local expected_total = 20 + 8 + #new_dns
      assert.equals(expected_total, #result, "longueur totale du paquet")
      local ip_len = bit.bor(bit.lshift(result:byte(3), 8), result:byte(4))
      assert.equals(expected_total, ip_len, "IP total_len mis à jour")
      local udp_len_field = bit.bor(bit.lshift(result:byte(25), 8), result:byte(26))
      assert.equals(8 + #new_dns, udp_len_field, "UDP length mis à jour")
      return assert.equals(new_dns, result:sub(29, 28 + #new_dns), "payload DNS correct")
    end)
    return it("replace_dns_payload — IPv4 TCP : longueur IP et DNS prefix mis à jour", function()
      local dns_orig = make_dns("\x03foo\x03com\x00", 1, false, 0x2222)
      local raw = make_ipv4_tcp_dns("8.8.8.8", "192.168.1.42", 53, 54321, dns_orig)
      local pkt = {
        ip = {
          version = 4,
          ihl = 20
        },
        l4 = {
          proto = "tcp"
        },
        tcp_init_seq = 0
      }
      local new_dns = dns_orig .. "\xAB\xCD"
      local result = replace_dns_payload(raw, pkt, new_dns)
      assert.is_not_nil(result, "replace_dns_payload TCP ne doit pas retourner nil")
      local expected_total = 20 + 20 + 2 + #new_dns
      assert.equals(expected_total, #result, "longueur totale TCP")
      local ip_len = bit.bor(bit.lshift(result:byte(3), 8), result:byte(4))
      assert.equals(expected_total, ip_len, "IP total_len mis à jour")
      local dns_prefix = bit.bor(bit.lshift(result:byte(41), 8), result:byte(42))
      assert.equals(#new_dns, dns_prefix, "DNS length prefix (TCP) = longueur DNS")
      return assert.equals(new_dns, result:sub(43, 42 + #new_dns), "payload DNS TCP correct")
    end)
  end)
end)
describe("parse/ndpi — ndpi_v5 backend", function()
  return it("major=5 charge le backend ndpi_v5", function()
    package.loaded["parse.ndpi"] = nil
    package.loaded["ffi_ndpi"] = {
      ffi = ffi,
      ndpi_lib = { },
      major = 5
    }
    local m5 = dofile("lua/parse/ndpi.lua")
    assert.is_not_nil(m5, "module ndpi chargé avec major=5")
    assert.is_not_nil(m5.parse_packet, "parse_packet exporté")
    assert.is_not_nil(m5.purge_flows, "purge_flows exporté")
    package.loaded["parse.ndpi"] = nil
    package.loaded["ffi_ndpi"] = {
      ffi = ffi,
      ndpi_lib = { },
      major = 4
    }
  end)
end)
describe("parse/ndpi — constantes QTYPE et RCODE", function()
  it("QTYPE.ANY == 255", function()
    return assert.equals(255, m_ndpi.QTYPE.ANY)
  end)
  it("RCODE.REFUSED == 5", function()
    return assert.equals(5, m_ndpi.RCODE.REFUSED)
  end)
  return it("QTYPE_NAME[255] == 'ANY'", function()
    return assert.equals("ANY", m_ndpi.QTYPE_NAME[255])
  end)
end)
describe("parse/ndpi — purge_flows et purge_tcp_buffers", function()
  local fresh_ndpi_with_flow
  fresh_ndpi_with_flow = function()
    package.loaded["parse.ndpi"] = nil
    package.loaded["ffi_ndpi"] = {
      ffi = ffi,
      ndpi_lib = {
        ndpi_detection_get_sizeof_ndpi_flow_struct = function()
          return 64
        end
      },
      major = 4
    }
    pcall(ffi.cdef, "typedef struct ndpi_flow_struct ndpi_flow_struct;")
    package.loaded["parse.ndpi_v4"] = {
      init = function()
        return nil
      end,
      detect = function()
        return 0, 0
      end,
      cleanup = function()
        return nil
      end
    }
    local m = dofile("lua/parse/ndpi.lua")
    package.loaded["parse.ndpi"] = nil
    package.loaded["ffi_ndpi"] = {
      ffi = ffi,
      ndpi_lib = { },
      major = 4
    }
    return m
  end
  it("purge_flows(0) s'exécute sans erreur (table vide)", function()
    local m = fresh_ndpi_with_flow()
    local ok, err = pcall(m.purge_flows, 0)
    return assert.is_true(ok, "purge_flows ne doit pas lever d'erreur: " .. tostring(err))
  end)
  it("purge_flows(300) avec défaut max_age", function()
    local m = fresh_ndpi_with_flow()
    local ok, err = pcall(m.purge_flows)
    return assert.is_true(ok, "purge_flows() sans argument ne doit pas lever d'erreur: " .. tostring(err))
  end)
  it("purge_tcp_buffers(0) s'exécute sans erreur", function()
    local m = fresh_ndpi_with_flow()
    local ok, err = pcall(m.purge_tcp_buffers, 0)
    return assert.is_true(ok, "purge_tcp_buffers ne doit pas lever d'erreur: " .. tostring(err))
  end)
  it("purge_tcp_buffers() avec défaut max_age", function()
    local m = fresh_ndpi_with_flow()
    local ok, err = pcall(m.purge_tcp_buffers)
    return assert.is_true(ok, "purge_tcp_buffers() sans argument: " .. tostring(err))
  end)
  it("purge_flows expire un flow créé dans le passé", function()
    local m = fresh_ndpi_with_flow()
    local dns = make_dns("\3foo\3bar\0", 1, false, 0xABCD)
    local raw = make_ipv4_tcp_dns("192.168.5.1", "8.8.8.8", 59990, 53, dns)
    parse_packet(raw)
    local ok, err = pcall(m.purge_flows, 0)
    return assert.is_true(ok, "purge_flows(0) apres flow: " .. tostring(err))
  end)
  return it("purge_tcp_buffers expire un buffer TCP créé dans le passé", function()
    local m = fresh_ndpi_with_flow()
    local dns = make_dns("\3baz\3qux\0", 1, false, 0xDEF0)
    local raw = make_ipv4_tcp_dns("192.168.6.1", "8.8.8.8", 59991, 53, dns)
    parse_packet(raw)
    local ok, err = pcall(m.purge_tcp_buffers, 0)
    return assert.is_true(ok, "purge_tcp_buffers(0) apres buffer: " .. tostring(err))
  end)
end)
describe("parse/ndpi — IPv6 Next Header 59 et inconnu", function()
  local src6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x42"
  local dst6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x01"
  local make_ipv6_bare
  make_ipv6_bare = function(nh)
    return string.char(0x60, 0, 0, 0, 0, 0, nh, 64) .. src6 .. dst6
  end
  it("IPv6 NH=59 (No Next Header) → parse_packet retourne nil", function()
    local raw = make_ipv6_bare(59)
    local pkt = parse_packet(raw)
    return assert.is_nil(pkt, "NH=59 doit retourner nil (pas de couche transport)")
  end)
  it("IPv6 NH=253 (inconnu) → parse_packet retourne nil", function()
    local raw = make_ipv6_bare(253)
    local pkt = parse_packet(raw)
    return assert.is_nil(pkt, "NH=253 (inconnu) doit retourner nil")
  end)
  it("IPv6 NH=0 (HBH) trop court → parse_packet retourne nil", function()
    local raw = make_ipv6_bare(0)
    local pkt = parse_packet(raw)
    return assert.is_nil(pkt, "HBH trop court doit retourner nil")
  end)
  return it("IPv6 NH=0 (HBH) un seul octet → parse_packet retourne nil", function()
    local raw = make_ipv6_bare(0) .. string.char(17)
    local pkt = parse_packet(raw)
    return assert.is_nil(pkt, "HBH 1-octet doit retourner nil")
  end)
end)
describe("parse/ndpi — IPv6 AH extension header (NH=51)", function()
  local src6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x42"
  local dst6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x01"
  return it("IPv6 + AH (NH=51, len=1 → 12B) + UDP DNS → parse OK", function()
    local dns = make_dns("\3www\6github\3com\0", 1, false)
    local ah = string.char(17, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    local raw = make_ipv6_ext_udp_dns(src6, dst6, 54326, 53, dns, 51, ah)
    local pkt = parse_packet(raw)
    assert.is_not_nil(pkt, "parse_packet nil avec AH header")
    assert.equals(6, pkt.ip.version)
    assert.equals("udp", pkt.l4.proto)
    return assert.equals(0x1234, pkt.dns.txid)
  end)
end)
describe("parse/ndpi — TCP tcp_control (flag RST/FIN, pas de données)", function()
  it("TCP ACK pur (0 payload, pas de buffer) → nil + tcp_control", function()
    local src_bytes = "\xC0\xA8\x01\x01"
    local dst_bytes = "\x08\x08\x08\x08"
    local total_len = 20 + 20
    local ip_hdr = string.char(0x45, 0, bit.rshift(bit.band(total_len, 0xFF00), 8), bit.band(total_len, 0xFF), 0, 1, 0, 0, 64, 6, 0, 0) .. src_bytes .. dst_bytes
    local tcp_hdr = string.char(0xD4, 0x31, 0, 53, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x10, 0x72, 0x10, 0, 0, 0, 0)
    local raw = ip_hdr .. tcp_hdr
    local pkt, status = parse_packet(raw)
    assert.is_nil(pkt, "TCP ACK pur doit retourner nil")
    return assert.equals("tcp_control", status, "statut doit être tcp_control")
  end)
  return it("TCP RST (flag 0x04) sans données → nil + tcp_control", function()
    local src_bytes = "\xC0\xA8\x01\x01"
    local dst_bytes = "\x08\x08\x08\x08"
    local total_len = 20 + 20
    local ip_hdr = string.char(0x45, 0, bit.rshift(bit.band(total_len, 0xFF00), 8), bit.band(total_len, 0xFF), 0, 1, 0, 0, 64, 6, 0, 0) .. src_bytes .. dst_bytes
    local tcp_hdr = string.char(0xD4, 0x32, 0, 53, 0, 0, 0, 2, 0, 0, 0, 0, 0x50, 0x04, 0x72, 0x10, 0, 0, 0, 0)
    local raw = ip_hdr .. tcp_hdr
    local pkt, status = parse_packet(raw)
    assert.is_nil(pkt, "TCP RST sans données → nil")
    return assert.equals("tcp_control", status)
  end)
end)
describe("parse/ndpi — patch_and_checksum IPv6 UDP (fix_udp6_cksum)", function()
  return it("patch_and_checksum sur IPv6 UDP recalcule le checksum correctement", function()
    local src6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x42"
    local dst6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x01"
    local qname_enc = "\x03www\x06github\x03com\x00"
    local hdr = string.char(0xAB, 0xCD, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0)
    local question = qname_enc .. string.char(0, 1, 0, 1)
    local rr = "\xC0\x0C" .. string.char(0, 1, 0, 1) .. string.char(0, 0, 1, 0x2C) .. string.char(0, 4) .. string.char(1, 2, 3, 4)
    local dns_payload = hdr .. question .. rr
    local raw = make_ipv6_udp_dns(src6, dst6, 54327, 53, dns_payload)
    local pkt = parse_packet(raw)
    assert.is_not_nil(pkt, "parse_packet IPv6 UDP retourne nil")
    assert.equals(6, pkt.ip.version)
    assert.equals("udp", pkt.l4.proto)
    local answers = m_ndpi.parse_answers(raw, pkt)
    assert.equals(1, #answers, "1 réponse attendue")
    local patched = patch_and_checksum(raw, pkt, answers, 60)
    assert.is_not_nil(patched, "patch_and_checksum IPv6 UDP retourne nil")
    return assert.equals(#raw, #patched, "longueur du paquet inchangée")
  end)
end)
return describe("parse/ndpi — patch_and_checksum IPv6 TCP (fix_tcp6_cksum)", function()
  return it("patch_and_checksum sur IPv6 TCP fonctionne", function()
    local src6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x42"
    local dst6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x01"
    local qname_enc = "\x03foo\x03bar\x00"
    local hdr = string.char(0xEF, 0x01, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0)
    local question = qname_enc .. string.char(0, 1, 0, 1)
    local rr = "\xC0\x0C" .. string.char(0, 1, 0, 1) .. string.char(0, 0, 1, 0x2C) .. string.char(0, 4) .. string.char(5, 6, 7, 8)
    local dns_payload = hdr .. question .. rr
    local dns_len = #dns_payload
    local pfx = string.char(bit.rshift(bit.band(dns_len, 0xFF00), 8), bit.band(dns_len, 0xFF))
    local tcp_payload = pfx .. dns_payload
    local pay_len = 20 + #tcp_payload
    local ip6 = string.char(0x60, 0, 0, 0, bit.rshift(bit.band(pay_len, 0xFF00), 8), bit.band(pay_len, 0xFF), 6, 64) .. src6 .. dst6
    local tcp_hdr6 = string.char(0xD4, 0x38, 0, 53, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x18, 0x72, 0x10, 0, 0, 0, 0)
    local raw = ip6 .. tcp_hdr6 .. tcp_payload
    local pkt = parse_packet(raw)
    assert.is_not_nil(pkt, "parse_packet IPv6 TCP retourne nil")
    assert.equals(6, pkt.ip.version)
    assert.equals("tcp", pkt.l4.proto)
    local answers = m_ndpi.parse_answers(raw, pkt)
    local patched = patch_and_checksum(raw, pkt, answers, 60)
    return assert.is_not_nil(patched, "patch_and_checksum IPv6 TCP retourne nil")
  end)
end)
