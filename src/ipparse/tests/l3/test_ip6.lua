local util = require("ipparse.lib.util")
local test
test = util.test
local ip6 = require("ipparse.l3.ip6")
test("ip62s converts 16 bytes to colon-hex", function()
  local bin = ip6.s2ip6("0:0:0:0:0:0:0:1")
  local result = ip6.ip62s(bin)
  return assert(result == "0:0:0:0:0:0:0:1", "expected '0:0:0:0:0:0:0:1', got '" .. tostring(result) .. "'")
end)
test("s2ip6 converts address to 16 bytes", function()
  local result = ip6.s2ip6("0:0:0:0:0:0:0:1")
  local expected = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
  return assert(result == expected, "s2ip6(0:0:0:0:0:0:0:1) mismatch")
end)
test("s2ip6 full address", function()
  local result = ip6.s2ip6("2001:db8:0:0:0:0:0:1")
  return assert(#result == 16, "s2ip6 should return 16 bytes, got " .. tostring(#result))
end)
test("ip62s/s2ip6 round-trip preserves bytes", function()
  local original = "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
  local converted = ip6.s2ip6(ip6.ip62s(original))
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
