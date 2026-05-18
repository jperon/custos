local util = require("ipparse.lib.util")
local test
test = util.test
local eth = require("ipparse.l2.ethernet")
local sp = require("ipparse.lib.pack_compat").pack
local eth_raw = sp("c6c6>H", "\xaa\xbb\xcc\xdd\xee\xff", "\x00\x11\x22\x33\x44\x55", 0x0800)
test("mac2s converts binary to string", function()
  local result = eth.mac2s("\xaa\xbb\xcc\xdd\xee\xff")
  return assert(result == "aa:bb:cc:dd:ee:ff", "expected 'aa:bb:cc:dd:ee:ff', got '" .. tostring(result) .. "'")
end)
test("s2mac converts string to binary", function()
  local result = eth.s2mac("aa:bb:cc:dd:ee:ff")
  return assert(result == "\xaa\xbb\xcc\xdd\xee\xff", "s2mac failed")
end)
test("mac2s/s2mac round-trip", function()
  local original = "\x12\x34\x56\x78\x9a\xbc"
  return assert(eth.s2mac(eth.mac2s(original)) == original, "mac2s/s2mac round-trip failed")
end)
test("parse extracts dst MAC", function()
  local frame, next_off = eth.parse(eth_raw, 1)
  return assert(frame.dst == "\xaa\xbb\xcc\xdd\xee\xff", "dst MAC mismatch")
end)
test("parse extracts src MAC", function()
  local frame, next_off = eth.parse(eth_raw, 1)
  return assert(frame.src == "\x00\x11\x22\x33\x44\x55", "src MAC mismatch")
end)
test("parse extracts protocol", function()
  local frame, next_off = eth.parse(eth_raw, 1)
  return assert(frame.protocol == 0x0800, "protocol should be 0x0800, got " .. tostring(frame.protocol))
end)
test("parse returns correct next offset", function()
  local frame, next_off = eth.parse(eth_raw, 1)
  return assert(next_off == 15, "next_off should be 15 (after 14-byte header), got " .. tostring(next_off))
end)
test("parse data_off is 15", function()
  local frame, next_off = eth.parse(eth_raw, 1)
  return assert(frame.data_off == 15, "data_off should be 15, got " .. tostring(frame.data_off))
end)
test("proto IP4 == 0x0800", function()
  return assert(eth.proto.IP4 == 0x0800, "IP4 proto should be 0x0800, got " .. tostring(eth.proto.IP4))
end)
test("proto reverse lookup 0x0800 == IP4", function()
  return assert(eth.proto[0x0800] == "IP4", "reverse lookup 0x0800 should be 'IP4', got '" .. tostring(eth.proto[0x0800]) .. "'")
end)
test("proto IP6 == 0x86DD", function()
  return assert(eth.proto.IP6 == 0x86DD, "IP6 proto should be 0x86DD")
end)
test("new + tostring round-trip", function()
  local frame = eth.new({
    dst = "\xaa\xbb\xcc\xdd\xee\xff",
    src = "\x00\x11\x22\x33\x44\x55",
    protocol = 0x0800
  })
  local raw = tostring(frame)
  local parsed, _ = eth.parse(raw, 1)
  assert(parsed.dst == "\xaa\xbb\xcc\xdd\xee\xff", "round-trip dst mismatch")
  assert(parsed.src == "\x00\x11\x22\x33\x44\x55", "round-trip src mismatch")
  return assert(parsed.protocol == 0x0800, "round-trip protocol mismatch")
end)
local eth_vlan_raw = sp("c6c6>HHH", "\xaa\xbb\xcc\xdd\xee\xff", "\x00\x11\x22\x33\x44\x55", 0x8100, 6, 0x0800)
test("parse detects 802.1Q tag and extracts vlan", function()
  local frame, next_off = eth.parse(eth_vlan_raw, 1)
  return assert(frame.vlan == 6, "vlan should be 6, got " .. tostring(frame.vlan))
end)
test("parse 802.1Q: inner protocol is correct", function()
  local frame, _ = eth.parse(eth_vlan_raw, 1)
  return assert(frame.protocol == 0x0800, "inner protocol should be 0x0800, got " .. tostring(frame.protocol))
end)
test("parse 802.1Q: data_off is 19 (18-byte header + 1-based)", function()
  local frame, next_off = eth.parse(eth_vlan_raw, 1)
  assert(frame.data_off == 19, "data_off should be 19, got " .. tostring(frame.data_off))
  return assert(next_off == 19, "next_off should be 19, got " .. tostring(next_off))
end)
test("parse untagged frame: vlan is nil", function()
  local frame, _ = eth.parse(eth_raw, 1)
  return assert(frame.vlan == nil, "vlan should be nil for untagged frame, got " .. tostring(frame.vlan))
end)
test("new with vlan: tostring produces 802.1Q frame", function()
  local frame = eth.new({
    dst = "\xaa\xbb\xcc\xdd\xee\xff",
    src = "\x00\x11\x22\x33\x44\x55",
    protocol = 0x0800,
    vlan = 6
  })
  return assert(tostring(frame) == eth_vlan_raw, "VLAN-tagged frame bytes mismatch")
end)
test("new with vlan=0: tostring produces plain frame (no tag)", function()
  local frame = eth.new({
    dst = "\xaa\xbb\xcc\xdd\xee\xff",
    src = "\x00\x11\x22\x33\x44\x55",
    protocol = 0x0800,
    vlan = 0
  })
  return assert(tostring(frame) == eth_raw, "vlan=0 should produce plain frame")
end)
test("new + tostring round-trip with vlan", function()
  local frame = eth.new({
    dst = "\xaa\xbb\xcc\xdd\xee\xff",
    src = "\x00\x11\x22\x33\x44\x55",
    protocol = 0x0800,
    vlan = 42
  })
  local parsed, _ = eth.parse(tostring(frame), 1)
  assert(parsed.vlan == 42, "round-trip vlan mismatch: got " .. tostring(parsed.vlan))
  assert(parsed.protocol == 0x0800, "round-trip protocol mismatch")
  return assert(parsed.dst == "\xaa\xbb\xcc\xdd\xee\xff", "round-trip dst mismatch")
end)
return util.summary("l2/ethernet")
