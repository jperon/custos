local util = require("ipparse.lib.util")
local test
test = util.test
local udp = require("ipparse.l4.udp")
test("parse extracts spt, dpt, len, checksum", function()
  local u = udp.new({
    spt = 12345,
    dpt = 53,
    checksum = 0
  })
  local raw = tostring(u)
  local parsed, _ = udp.parse(raw, 1)
  assert(parsed.spt == 12345, "spt should be 12345, got " .. tostring(parsed.spt))
  assert(parsed.dpt == 53, "dpt should be 53, got " .. tostring(parsed.dpt))
  assert(parsed.len == 8, "len should be 8 (no data), got " .. tostring(parsed.len))
  return assert(parsed.checksum == 0, "checksum should be 0, got " .. tostring(parsed.checksum))
end)
test("pack sets len=8 when no data", function()
  local u = udp.new({
    spt = 1000,
    dpt = 2000,
    checksum = 0
  })
  local raw = tostring(u)
  local parsed, _ = udp.parse(raw, 1)
  return assert(parsed.len == 8, "len should be 8 with no data, got " .. tostring(parsed.len))
end)
test("pack sets len=8+data_len when data present", function()
  local u = udp.new({
    spt = 1000,
    dpt = 2000,
    checksum = 0,
    data = "hello"
  })
  local raw = tostring(u)
  local parsed, _ = udp.parse(raw, 1)
  return assert(parsed.len == 13, "len should be 13 (8+5), got " .. tostring(parsed.len))
end)
test("round-trip: new -> tostring -> parse", function()
  local u = udp.new({
    spt = 5678,
    dpt = 1234,
    checksum = 0xabcd
  })
  local raw = tostring(u)
  local parsed, _ = udp.parse(raw, 1)
  assert(parsed.spt == 5678, "round-trip spt mismatch")
  assert(parsed.dpt == 1234, "round-trip dpt mismatch")
  return assert(parsed.checksum == 0xabcd, "round-trip checksum mismatch")
end)
test("data_off is off+8", function()
  local u = udp.new({
    spt = 100,
    dpt = 200,
    checksum = 0
  })
  local raw = tostring(u)
  local parsed, _ = udp.parse(raw, 1)
  return assert(parsed.data_off == 9, "data_off should be 9 (1+8), got " .. tostring(parsed.data_off))
end)
test("packed output is 8 bytes with no data", function()
  local u = udp.new({
    spt = 100,
    dpt = 200,
    checksum = 0
  })
  local raw = tostring(u)
  return assert(#raw == 8, "UDP header with no data should be 8 bytes, got " .. tostring(#raw))
end)
test("packed output includes data", function()
  local u = udp.new({
    spt = 100,
    dpt = 200,
    checksum = 0,
    data = "abc"
  })
  local raw = tostring(u)
  return assert(#raw == 11, "UDP with 3-byte data should be 11 bytes, got " .. tostring(#raw))
end)
return util.summary("l4/udp")
