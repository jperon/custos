local util = require("ipparse.lib.util")
local test
test = util.test
local ip4 = require("ipparse.l3.ip4")
test("ip42s converts 4 bytes to dotted decimal", function()
  local result = ip4.ip42s("\xc0\xa8\x01\x01")
  return assert(result == "192.168.1.1", "expected '192.168.1.1', got '" .. tostring(result) .. "'")
end)
test("s2ip4 converts dotted decimal to 4 bytes", function()
  local result = ip4.s2ip4("192.168.1.1")
  return assert(result == "\xc0\xa8\x01\x01", "s2ip4 failed")
end)
test("ip42s/s2ip4 round-trip", function()
  local original = "\x0a\x00\x00\x01"
  return assert(ip4.s2ip4(ip4.ip42s(original)) == original, "ip42s/s2ip4 round-trip failed")
end)
test("net42s converts 5 bytes to CIDR notation", function()
  local bin = "\x18\xc0\xa8\x01\x00"
  local result = ip4.net42s(bin)
  return assert(result == "192.168.1.0/24", "expected '192.168.1.0/24', got '" .. tostring(result) .. "'")
end)
test("s2net4 converts CIDR to 5 bytes", function()
  local result = ip4.s2net4("192.168.1.0/24")
  return assert(result == "\x18\xc0\xa8\x01\x00", "s2net4 failed")
end)
test("net42s/s2net4 round-trip", function()
  local original = "10.0.0.0/8"
  return assert(ip4.net42s(ip4.s2net4(original)) == original, "net42s/s2net4 round-trip failed")
end)
test("parse extracts version=4", function()
  local hdr = ip4.new({
    src = ip4.s2ip4("1.2.3.4"),
    dst = ip4.s2ip4("5.6.7.8"),
    protocol = 17,
    options = ""
  })
  local raw = tostring(hdr)
  local parsed, _ = ip4.parse(raw, 1)
  return assert(parsed.version == 4, "version should be 4, got " .. tostring(parsed.version))
end)
test("parse extracts protocol", function()
  local hdr = ip4.new({
    src = ip4.s2ip4("1.2.3.4"),
    dst = ip4.s2ip4("5.6.7.8"),
    protocol = 17,
    options = ""
  })
  local raw = tostring(hdr)
  local parsed, _ = ip4.parse(raw, 1)
  return assert(parsed.protocol == 17, "protocol should be 17, got " .. tostring(parsed.protocol))
end)
test("parse extracts src and dst", function()
  local src = ip4.s2ip4("192.168.1.1")
  local dst = ip4.s2ip4("192.168.1.2")
  local hdr = ip4.new({
    src = src,
    dst = dst,
    protocol = 6,
    options = ""
  })
  local raw = tostring(hdr)
  local parsed, _ = ip4.parse(raw, 1)
  assert(parsed.src == src, "src mismatch")
  return assert(parsed.dst == dst, "dst mismatch")
end)
test("new sets default ttl=64", function()
  local hdr = ip4.new({
    src = ip4.s2ip4("1.2.3.4"),
    dst = ip4.s2ip4("5.6.7.8"),
    protocol = 6,
    options = ""
  })
  return assert(hdr.ttl == 64, "default ttl should be 64, got " .. tostring(hdr.ttl))
end)
test("new sets default version=4", function()
  local hdr = ip4.new({
    src = ip4.s2ip4("1.2.3.4"),
    dst = ip4.s2ip4("5.6.7.8"),
    protocol = 6,
    options = ""
  })
  return assert(hdr.version == 4, "default version should be 4, got " .. tostring(hdr.version))
end)
test("pack calculates non-zero checksum", function()
  local hdr = ip4.new({
    src = ip4.s2ip4("1.2.3.4"),
    dst = ip4.s2ip4("5.6.7.8"),
    protocol = 6,
    options = ""
  })
  local raw = tostring(hdr)
  local parsed, _ = ip4.parse(raw, 1)
  return assert(parsed.checksum ~= 0, "checksum should be non-zero for non-trivial header")
end)
test("data_off is off+20 for IHL=5", function()
  local hdr = ip4.new({
    src = ip4.s2ip4("1.2.3.4"),
    dst = ip4.s2ip4("5.6.7.8"),
    protocol = 6,
    options = ""
  })
  local raw = tostring(hdr)
  local parsed, _ = ip4.parse(raw, 1)
  return assert(parsed.data_off == 21, "data_off should be 21 (1+20), got " .. tostring(parsed.data_off))
end)
test("DF flag readable via __index", function()
  local hdr = ip4.new({
    src = ip4.s2ip4("1.2.3.4"),
    dst = ip4.s2ip4("5.6.7.8"),
    protocol = 6,
    options = "",
    DF = true
  })
  return assert(hdr.DF == true, "DF flag should be true")
end)
test("DF flag false when not set", function()
  local hdr = ip4.new({
    src = ip4.s2ip4("1.2.3.4"),
    dst = ip4.s2ip4("5.6.7.8"),
    protocol = 6,
    options = ""
  })
  return assert(hdr.DF == false, "DF flag should be false when not set")
end)
test("DF flag settable via __newindex", function()
  local hdr = ip4.new({
    src = ip4.s2ip4("1.2.3.4"),
    dst = ip4.s2ip4("5.6.7.8"),
    protocol = 6,
    options = ""
  })
  hdr.DF = true
  return assert(hdr.DF == true, "DF flag should be true after setting")
end)
test("parse round-trip preserves ihl=5", function()
  local hdr = ip4.new({
    src = ip4.s2ip4("10.0.0.1"),
    dst = ip4.s2ip4("10.0.0.2"),
    protocol = 6,
    options = ""
  })
  local raw = tostring(hdr)
  local parsed, _ = ip4.parse(raw, 1)
  return assert(parsed.ihl == 5, "ihl should be 5, got " .. tostring(parsed.ihl))
end)
return util.summary("l3/ip4")
