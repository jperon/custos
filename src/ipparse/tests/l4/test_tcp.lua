local util = require("ipparse.lib.util")
local test
test = util.test
local tcp = require("ipparse.l4.tcp")
local mk_tcp
mk_tcp = function(opts)
  if opts == nil then
    opts = { }
  end
  return tcp.new({
    spt = opts.spt or 1234,
    dpt = opts.dpt or 80,
    seq_n = opts.seq_n or 0,
    ack_n = opts.ack_n or 0,
    header_len = 0x50,
    window = opts.window or 65535,
    checksum = 0,
    urg_ptr = 0,
    options = "",
    syn = opts.syn,
    ack = opts.ack,
    fin = opts.fin,
    rst = opts.rst,
    psh = opts.psh
  })
end
test("parse extracts spt and dpt", function()
  local t = mk_tcp({
    spt = 4321,
    dpt = 80
  })
  local raw = tostring(t)
  local parsed, _ = tcp.parse(raw, 1)
  assert(parsed.spt == 4321, "spt should be 4321, got " .. tostring(parsed.spt))
  return assert(parsed.dpt == 80, "dpt should be 80, got " .. tostring(parsed.dpt))
end)
test("parse extracts seq_n", function()
  local t = mk_tcp({
    seq_n = 0xdeadbeef
  })
  local t2 = tcp.new({
    spt = 1234,
    dpt = 80,
    seq_n = 0xdeadbeef,
    ack_n = 0,
    header_len = 0x50,
    window = 65535,
    checksum = 0,
    urg_ptr = 0,
    options = ""
  })
  local raw = tostring(t2)
  local parsed, _ = tcp.parse(raw, 1)
  return assert(parsed.seq_n == 0xdeadbeef, "seq_n should be 0xdeadbeef, got " .. tostring(parsed.seq_n))
end)
test("SYN flag set via new", function()
  local t = mk_tcp({
    syn = true
  })
  return assert(t.SYN == true, "SYN should be true")
end)
test("ACK flag set via new", function()
  local t = mk_tcp({
    ack = true
  })
  return assert(t.ACK == true, "ACK should be true")
end)
test("FIN flag set via new", function()
  local t = mk_tcp({
    fin = true
  })
  return assert(t.FIN == true, "FIN should be true")
end)
test("RST flag set via new", function()
  local t = mk_tcp({
    rst = true
  })
  return assert(t.RST == true, "RST should be true")
end)
test("PSH flag set via new", function()
  local t = mk_tcp({
    psh = true
  })
  return assert(t.PSH == true, "PSH should be true")
end)
test("no flags set when none provided", function()
  local t = mk_tcp({ })
  assert(t.SYN == false, "SYN should be false")
  assert(t.ACK == false, "ACK should be false")
  return assert(t.FIN == false, "FIN should be false")
end)
test("SYN flag settable via __newindex", function()
  local t = mk_tcp({ })
  t.SYN = true
  return assert(t.SYN == true, "SYN should be true after setting")
end)
test("SYN flag clearable via __newindex", function()
  local t = mk_tcp({
    syn = true
  })
  t.SYN = false
  return assert(t.SYN == false, "SYN should be false after clearing")
end)
test("flags table: SYN == 0x02", function()
  assert(tcp.flags.SYN == 0x02, "SYN flag value should be 0x02")
  assert(tcp.flags.ACK == 0x10, "ACK flag value should be 0x10")
  return assert(tcp.flags.FIN == 0x01, "FIN flag value should be 0x01")
end)
test("flags bidirectional reverse lookup", function()
  return assert(tcp.flags[0x02] == "SYN", "reverse lookup 0x02 should be SYN")
end)
test("data_off is off+20 for standard header", function()
  local t = mk_tcp({ })
  local raw = tostring(t)
  local parsed, _ = tcp.parse(raw, 1)
  return assert(parsed.data_off == 21, "data_off should be 21 (1+20), got " .. tostring(parsed.data_off))
end)
test("round-trip: new -> tostring -> parse", function()
  local t = mk_tcp({
    spt = 9999,
    dpt = 443,
    syn = true
  })
  local raw = tostring(t)
  local parsed, _ = tcp.parse(raw, 1)
  assert(parsed.spt == 9999, "round-trip spt mismatch")
  assert(parsed.dpt == 443, "round-trip dpt mismatch")
  return assert(parsed.SYN == true, "round-trip SYN flag mismatch")
end)
test("options empty in standard header", function()
  local t = mk_tcp({ })
  local raw = tostring(t)
  local parsed, _ = tcp.parse(raw, 1)
  return assert(parsed.options == "", "options should be empty string, got '" .. tostring(parsed.options) .. "'")
end)
return util.summary("l4/tcp")
