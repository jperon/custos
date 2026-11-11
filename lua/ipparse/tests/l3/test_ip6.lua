local util = require("ipparse.lib.util")
local test
test = util.test
local ip6 = require("ipparse.l3.ip6")
local udp = require("ipparse.l4.udp")
local checksum6
checksum6 = require("ipparse.l3.lib").checksum6
local su
su = require("ipparse.lib.pack_compat").unpack
test("ip62s compresses zero runs per RFC 5952", function()
  local bin = ip6.s2ip6("0:0:0:0:0:0:0:1")
  local result = ip6.ip62s(bin)
  return assert(result == "::1", "expected '::1', got '" .. tostring(result) .. "'")
end)
test("s2ip6 converts address to 16 bytes", function()
  local result = ip6.s2ip6("0:0:0:0:0:0:0:1")
  local expected = "\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\001"
  return assert(result == expected, "s2ip6(0:0:0:0:0:0:0:1) mismatch")
end)
test("s2ip6 full address", function()
  local result = ip6.s2ip6("2001:db8:0:0:0:0:0:1")
  return assert(#result == 16, "s2ip6 should return 16 bytes, got " .. tostring(#result))
end)
test("ip62s/s2ip6 round-trip preserves bytes", function()
  local original = "\032\001\013\184\000\000\000\000\000\000\000\000\000\000\000\001"
  local s = ip6.ip62s(original)
  assert(s == "2001:db8::1", "expected '2001:db8::1', got '" .. tostring(s) .. "'")
  local converted = ip6.s2ip6(s)
  return assert(converted == original, "ip62s/s2ip6 round-trip failed")
end)
test("parse extracts version=6", function()
  local hdr = ip6.new({
    src = ip6.s2ip6("::1"),
    dst = ip6.s2ip6("::2"),
    next_header = 17
  })
  local raw = tostring(hdr)
  local parsed, _ = ip6.parse(raw, 1)
  return assert(parsed.version == 6, "version should be 6, got " .. tostring(parsed.version))
end)
test("parse extracts next_header", function()
  local hdr = ip6.new({
    src = ip6.s2ip6("::1"),
    dst = ip6.s2ip6("::2"),
    next_header = 17
  })
  local raw = tostring(hdr)
  local parsed, _ = ip6.parse(raw, 1)
  return assert(parsed.next_header == 17, "next_header should be 17, got " .. tostring(parsed.next_header))
end)
test("parse extracts hop_limit", function()
  local hdr = ip6.new({
    src = ip6.s2ip6("::1"),
    dst = ip6.s2ip6("::2"),
    next_header = 6,
    hop_limit = 128
  })
  local raw = tostring(hdr)
  local parsed, _ = ip6.parse(raw, 1)
  return assert(parsed.hop_limit == 128, "hop_limit should be 128, got " .. tostring(parsed.hop_limit))
end)
test("new sets default hop_limit=64", function()
  local hdr = ip6.new({
    src = ip6.s2ip6("::1"),
    dst = ip6.s2ip6("::2"),
    next_header = 6
  })
  return assert(hdr.hop_limit == 64, "default hop_limit should be 64, got " .. tostring(hdr.hop_limit))
end)
test("new sets default version=6", function()
  local hdr = ip6.new({
    src = ip6.s2ip6("::1"),
    dst = ip6.s2ip6("::2"),
    next_header = 6
  })
  return assert(hdr.version == 6, "version should be 6, got " .. tostring(hdr.version))
end)
test("round-trip preserves src and dst", function()
  local src = ip6.s2ip6("::1")
  local dst = ip6.s2ip6("::2")
  local hdr = ip6.new({
    src = src,
    dst = dst,
    next_header = 17
  })
  local raw = tostring(hdr)
  local parsed, _ = ip6.parse(raw, 1)
  assert(parsed.src == src, "src mismatch after round-trip")
  return assert(parsed.dst == dst, "dst mismatch after round-trip")
end)
test("s2net6 defaults to /128 when no mask given", function()
  local result = ip6.s2net6("::1")
  assert(#result == 17, "s2net6 should return 17 bytes, got " .. tostring(#result))
  local mask = result:byte(1)
  return assert(mask == 128, "default mask should be 128, got " .. tostring(mask))
end)
test("pack recomputes vtf from traffic_class", function()
  local p = ip6.new({
    src = ip6.s2ip6("::1"),
    dst = ip6.s2ip6("::2"),
    next_header = 17
  })
  p.traffic_class = 0xff
  local raw = tostring(p)
  local second = raw:byte(2)
  return assert(second == 0xf0, "second octet should be 0xf0, got " .. tostring(second))
end)
test("re-packed parsed IPv6 header is byte-identical", function()
  local hdr = ip6.new({
    src = ip6.s2ip6("2001:db8::1"),
    dst = ip6.s2ip6("2001:db8::2"),
    next_header = 17,
    traffic_class = 0xab,
    flow_label = 0x12345
  })
  local raw1 = tostring(hdr)
  local parsed, _ = ip6.parse(raw1, 1)
  local raw2 = tostring(parsed)
  return assert(raw2 == raw1, "re-packed parsed header should be identical")
end)
test("UDP/IPv6 pack emits 0xFFFF for a zero checksum", function()
  local src = ip6.s2ip6("2001:db8::1")
  local dst = ip6.s2ip6("2001:db8::2")
  local segment = udp.new({
    spt = 1234,
    dpt = 53,
    checksum = 0,
    data = "\159\094"
  })
  local hdr = ip6.new({
    src = src,
    dst = dst,
    next_header = 17,
    data = segment
  })
  local raw = tostring(hdr)
  local csum = su(">H", raw, 47)
  assert(csum == 0xffff, "zero UDP checksum should be emitted as 0xFFFF, got " .. tostring(csum))
  local verify = checksum6(src, dst, 17, raw:sub(41))
  return assert(verify == 0, "UDP checksum should verify, got " .. tostring(verify))
end)
test("data_off is off+40 for IPv6 header", function()
  local hdr = ip6.new({
    src = ip6.s2ip6("::1"),
    dst = ip6.s2ip6("::2"),
    next_header = 17
  })
  local raw = tostring(hdr)
  local parsed, next_off = ip6.parse(raw, 1)
  return assert(parsed.data_off == 41, "data_off should be 41 (1+40), got " .. tostring(parsed.data_off))
end)
return util.summary("l3/ip6")
