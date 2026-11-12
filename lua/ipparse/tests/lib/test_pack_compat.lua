local util = require("ipparse.lib.util")
local test
test = util.test
local pack_compat = require("ipparse.lib.pack_compat")
local pack = pack_compat.pack or string.pack
local is_fallback = pack ~= string.pack
local from_hex
from_hex = function(h)
  local out = h:gsub("..", function(cc)
    return string.char(tonumber(cc, 16))
  end)
  return out
end
local tunpack = unpack or table.unpack
test("pack_compat: >H B B H H H H", function()
  local got = pack(">H B B H H H H", 1, 2, 3, 4, 5, 6, 7)
  local expected = from_hex("000102030004000500060007")
  return assert(got == expected, "got: " .. tostring(got) .. "\nexp: " .. tostring(expected))
end)
test("pack_compat: >H H I4 s2", function()
  local got = pack(">H H I4 s2", 1, 1, 300, "abcd")
  local expected = from_hex("000100010000012c000461626364")
  return assert(got == expected, "got: " .. tostring(got) .. "\nexp: " .. tostring(expected))
end)
test("pack_compat: <I4", function()
  local got = pack("<I4", 0x01020304)
  local expected = from_hex("04030201")
  return assert(got == expected, "got: " .. tostring(got) .. "\nexp: " .. tostring(expected))
end)
test("pack_compat: >i2 negative", function()
  local got = pack(">i2", -2)
  local expected = from_hex("fffe")
  return assert(got == expected, "got: " .. tostring(got) .. "\nexp: " .. tostring(expected))
end)
test("pack_compat: >c4 short", function()
  local got = pack(">c4", "ab")
  local expected = from_hex("61620000")
  return assert(got == expected, "got: " .. tostring(got) .. "\nexp: " .. tostring(expected))
end)
if is_fallback then
  test("pack_compat: >c4 long", function()
    local got = pack(">c4", "abcdef")
    local expected = from_hex("61626364")
    return assert(got == expected, "got: " .. tostring(got) .. "\nexp: " .. tostring(expected))
  end)
end
test("pack_compat: >H c4 ends with a buffer write", function()
  local got = pack(">H c4", 0x0102, "ab")
  local expected = from_hex("010261620000")
  return assert(got == expected, "got: " .. tostring(got) .. "\nexp: " .. tostring(expected))
end)
test("pack_compat: >H s2 c4 mixes emit and buffer write", function()
  local got = pack(">H s2 c4", 1, "xy", "ab")
  local expected = from_hex("00010002787961620000")
  return assert(got == expected, "got: " .. tostring(got) .. "\nexp: " .. tostring(expected))
end)
test("pack_compat: c64/c65/c80 identical full and padded", function()
  local _list_0 = {
    1,
    2,
    63,
    64,
    65,
    80
  }
  for _index_0 = 1, #_list_0 do
    local sz = _list_0[_index_0]
    local full = string.rep("A", sz)
    local got = pack(">c" .. tostring(sz), full)
    assert(got == full, "c" .. tostring(sz) .. " full input: got " .. tostring(#got) .. " bytes, expected " .. tostring(sz))
    local pad = pack(">c" .. tostring(sz), "A")
    assert(pad == "A" .. string.rep("\0", sz - 1), "c" .. tostring(sz) .. " padded: got " .. tostring(#pad) .. " bytes, expected " .. tostring(sz))
  end
end)
test("pack_compat: z", function()
  local got = pack("z", "hello")
  local expected = from_hex("68656c6c6f00")
  return assert(got == expected, "got: " .. tostring(got) .. "\nexp: " .. tostring(expected))
end)
test("pack_compat: x", function()
  local got = pack("x")
  local expected = from_hex("00")
  return assert(got == expected, "got: " .. tostring(got) .. "\nexp: " .. tostring(expected))
end)
test("pack_compat: >I3", function()
  local got = pack(">I3", 0x010203)
  local expected = from_hex("010203")
  return assert(got == expected, "got: " .. tostring(got) .. "\nexp: " .. tostring(expected))
end)
if is_fallback then
  test("pack_compat: B 300 wraps", function()
    local got = pack("B", 300)
    local expected = from_hex("2c")
    return assert(got == expected, "got: " .. tostring(got) .. "\nexp: " .. tostring(expected))
  end)
end
test("pack_compat: >B x10 more than 8 args", function()
  local got = pack(">B B B B B B B B B B", 1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
  local expected = from_hex("0102030405060708090a")
  return assert(got == expected, "got: " .. tostring(got) .. "\nexp: " .. tostring(expected))
end)
test("pack_compat: 16 args fill the shared array", function()
  local got = pack(">B B B B B B B B B B B B B B B B", 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16)
  local expected = from_hex("0102030405060708090a0b0c0d0e0f10")
  return assert(got == expected, "got: " .. tostring(got) .. "\nexp: " .. tostring(expected))
end)
test("pack_compat: more than 16 args uses the vararg path", function()
  local fmt = ">B " .. string.rep("B ", 16)
  local got = pack(fmt, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17)
  local expected = from_hex("0102030405060708090a0b0c0d0e0f1011")
  return assert(got == expected, "got: " .. tostring(got) .. "\nexp: " .. tostring(expected))
end)
test("pack_compat: >H x H", function()
  local got = pack(">H x H", 1, 2)
  local expected = from_hex("0001000002")
  return assert(got == expected, "got: " .. tostring(got) .. "\nexp: " .. tostring(expected))
end)
test("pack_compat: >H c2 H", function()
  local got = pack(">H c2 H", 1, "ab", 2)
  local expected = from_hex("000161620002")
  return assert(got == expected, "got: " .. tostring(got) .. "\nexp: " .. tostring(expected))
end)
test("pack_compat: >H z H", function()
  local got = pack(">H z H", 1, "ab", 2)
  local expected = from_hex("00016162000002")
  return assert(got == expected, "got: " .. tostring(got) .. "\nexp: " .. tostring(expected))
end)
test("pack_compat: >H s2 H", function()
  local got = pack(">H s2 H", 1, "ab", 2)
  local expected = from_hex("0001000261620002")
  return assert(got == expected, "got: " .. tostring(got) .. "\nexp: " .. tostring(expected))
end)
test("pack_compat: >i4 negative", function()
  local got = pack(">i4", -2)
  local expected = from_hex("fffffffe")
  return assert(got == expected, "got: " .. tostring(got) .. "\nexp: " .. tostring(expected))
end)
test("pack_compat: <I8 above 32-bit range", function()
  local got = pack("<I8", 0x100000000)
  local expected = from_hex("0000000001000000")
  return assert(got == expected, "got: " .. tostring(got) .. "\nexp: " .. tostring(expected))
end)
test("pack_compat: empty format", function()
  local got = pack("")
  return assert(got == "", "got: " .. tostring(got))
end)
local unpack = pack_compat.unpack or string.unpack
test("pack_compat: >i8 negative bytes", function()
  local got = pack(">i8", -2)
  local expected = from_hex("fffffffffffffffe")
  return assert(got == expected, "got: " .. tostring(got) .. "\nexp: " .. tostring(expected))
end)
test("pack_compat: <i8 negative one bytes", function()
  local got = pack("<i8", -1)
  local expected = from_hex("ffffffffffffffff")
  return assert(got == expected, "got: " .. tostring(got) .. "\nexp: " .. tostring(expected))
end)
test("pack_compat: >i8 negative 2^53 bytes", function()
  local got = pack(">i8", -9007199254740992)
  local expected = from_hex("ffe0000000000000")
  return assert(got == expected, "got: " .. tostring(got) .. "\nexp: " .. tostring(expected))
end)
test("pack_compat: <I8 above 32-bit range bytes", function()
  local got = pack("<I8", 0x100000000)
  local expected = from_hex("0000000001000000")
  return assert(got == expected, "got: " .. tostring(got) .. "\nexp: " .. tostring(expected))
end)
test("pack_compat: =I4 native little-endian", function()
  local got = pack("=I4", 0x01020304)
  local expected = from_hex("04030201")
  return assert(got == expected, "got: " .. tostring(got) .. "\nexp: " .. tostring(expected))
end)
test("pack_compat: >i8 negative round-trip", function()
  local v, pos = unpack(">i8", pack(">i8", -2))
  assert(v == -2, "got: " .. tostring(v))
  return assert(pos == 9, "pos: " .. tostring(pos))
end)
test("pack_compat: unpack B on empty string raises", function()
  local ok, err = pcall(unpack, "B", "", 1)
  return assert(not ok and tostring(err):match("too short"), "expected 'data string too short', got: " .. tostring(tostring(err)))
end)
test("pack_compat: unpack c8 on 3-byte string raises", function()
  local ok, err = pcall(unpack, "c8", "abc", 1)
  return assert(not ok and tostring(err):match("too short"), "expected 'data string too short', got: " .. tostring(tostring(err)))
end)
test("pack_compat: unpack >s1 with truncated body raises", function()
  local ok, err = pcall(unpack, ">s1", "\005ab", 1)
  return assert(not ok and tostring(err):match("too short"), "expected 'data string too short', got: " .. tostring(tostring(err)))
end)
test("pack_compat: unpack full-width controls still work", function()
  assert(unpack("B", "a", 1) == 97, "B on 'a'")
  assert(unpack("c3", "abc", 1) == "abc", "c3 on 'abc'")
  assert(unpack(">s1", "\002ab", 1) == "ab", "s1 on '\\002ab'")
  return assert(unpack("c0", "", 1) == "", "c0 on ''")
end)
test("pack_compat: B round-trip", function()
  local packed = pack("B", 35)
  local result, pos = unpack("B", packed)
  assert(result == 35, "got: " .. tostring(result))
  return assert(pos == 2, "pos: " .. tostring(pos))
end)
test("pack_compat: I round-trip", function()
  local packed = pack("I", 35)
  local result, pos = unpack("I", packed)
  assert(result == 35, "got: " .. tostring(result))
  return assert(pos == 5, "pos: " .. tostring(pos))
end)
test("pack_compat: s2 round-trip", function()
  local packed = pack("s2", "he")
  local result, pos = unpack("s2", packed)
  assert(result == "he", "got: " .. tostring(result))
  return assert(pos == 2 * #result + 1, "pos: " .. tostring(pos))
end)
test("pack_compat: b/B endianness and unpack", function()
  assert(pack(">b", -1) == from_hex("ff", ">b -1"))
  assert(pack("<b", -1) == from_hex("ff", "<b -1"))
  assert(pack(">B", 255) == from_hex("ff", ">B 255"))
  assert(pack("<B", 255) == from_hex("ff", "<B 255"))
  local v, pos = unpack(">b", from_hex("fe"))
  assert(v == -2 and pos == 2, "unpack >b -2 (got " .. tostring(v) .. ", " .. tostring(pos) .. ")")
  v, pos = unpack("<B", from_hex("fe"))
  return assert(v == 254 and pos == 2, "unpack <B 254 (got " .. tostring(v) .. ", " .. tostring(pos) .. ")")
end)
test("pack_compat: h/H endianness and unpack", function()
  assert(pack(">h", -2) == from_hex("fffe", ">h -2"))
  assert(pack("<h", -2) == from_hex("feff", "<h -2"))
  assert(pack(">H", 513) == from_hex("0201", ">H 513"))
  assert(pack("<H", 513) == from_hex("0102", "<H 513"))
  local v, pos = unpack(">h", from_hex("fffe"))
  assert(v == -2 and pos == 3, "unpack >h -2 (got " .. tostring(v) .. ", " .. tostring(pos) .. ")")
  v, pos = unpack("<H", from_hex("0102"))
  return assert(v == 513 and pos == 3, "unpack <H 513 (got " .. tostring(v) .. ", " .. tostring(pos) .. ")")
end)
test("pack_compat: I3 endianness and unpack", function()
  assert(pack(">I3", 0x010203) == from_hex("010203", ">I3"))
  assert(pack("<I3", 0x010203) == from_hex("030201", "<I3"))
  local v, pos = unpack("<I3", from_hex("030201"))
  return assert(v == 0x010203 and pos == 4, "unpack <I3 (got " .. tostring(v) .. ", " .. tostring(pos) .. ")")
end)
test("pack_compat: I5/I6 bytes", function()
  assert(pack(">I5", 0x0102030405) == from_hex("0102030405", ">I5"))
  assert(pack("<I5", 0x0102030405) == from_hex("0504030201", "<I5"))
  assert(pack(">I6", 0x010203040506) == from_hex("010203040506", ">I6"))
  assert(pack("<I6", 0x010203040506) == from_hex("060504030201", "<I6"))
  local v, pos = unpack(">I5", from_hex("0102030405"))
  assert(v == 0x0102030405 and pos == 6, "unpack >I5 (got " .. tostring(v) .. ", " .. tostring(pos) .. ")")
  v, pos = unpack("<I6", from_hex("060504030201"))
  return assert(v == 0x010203040506 and pos == 7, "unpack <I6 (got " .. tostring(v) .. ", " .. tostring(pos) .. ")")
end)
test("pack_compat: I7/I8 bytes and unpack", function()
  assert(pack(">I7", 0x01020304050607) == from_hex("01020304050607", ">I7"))
  assert(pack("<I7", 0x01020304050607) == from_hex("07060504030201", "<I7"))
  assert(pack(">I8", 0x0123456789abcd) == from_hex("000123456789abcd", ">I8"))
  assert(pack("<I8", 0x0123456789abcd) == from_hex("cdab896745230100", "<I8"))
  local v, pos = unpack(">I7", from_hex("01020304050607"))
  assert(v == 0x01020304050607 and pos == 8, "unpack >I7 (got " .. tostring(v) .. ", " .. tostring(pos) .. ")")
  v, pos = unpack("<I8", from_hex("cdab896745230100"))
  return assert(v == 0x0123456789abcd and pos == 9, "unpack <I8 (got " .. tostring(v) .. ", " .. tostring(pos) .. ")")
end)
test("pack_compat: signed i1..i4 limits", function()
  local sizes = {
    {
      1,
      -128,
      127
    },
    {
      2,
      -32768,
      32767
    },
    {
      3,
      -8388608,
      8388607
    },
    {
      4,
      -2147483648,
      2147483647
    }
  }
  for _index_0 = 1, #sizes do
    local item = sizes[_index_0]
    local sz, mn, mx = item[1], item[2], item[3]
    local fmt = ">" .. "i" .. sz
    local _list_0 = {
      mn,
      mx,
      -1,
      0
    }
    for _index_1 = 1, #_list_0 do
      local v = _list_0[_index_1]
      local got = pack(fmt, v)
      assert(#got == sz, tostring(fmt) .. ": width " .. tostring(#got) .. " != " .. tostring(sz))
      local r, pos = unpack(fmt, got)
      assert(r == v, tostring(fmt) .. " round-trip: " .. tostring(r) .. " != " .. tostring(v))
      assert(pos == sz + 1, tostring(fmt) .. " pos: " .. tostring(pos))
    end
  end
end)
test("pack_compat: unsigned I1..I4 limits", function()
  local sizes = {
    {
      1,
      255
    },
    {
      2,
      65535
    },
    {
      3,
      16777215
    },
    {
      4,
      4294967295
    }
  }
  for _index_0 = 1, #sizes do
    local item = sizes[_index_0]
    local sz, mx = item[1], item[2]
    local fmt = ">" .. "I" .. sz
    local _list_0 = {
      0,
      1,
      mx
    }
    for _index_1 = 1, #_list_0 do
      local v = _list_0[_index_1]
      local got = pack(fmt, v)
      assert(#got == sz, tostring(fmt) .. ": width " .. tostring(#got) .. " != " .. tostring(sz))
      local r, pos = unpack(fmt, got)
      assert(r == v, tostring(fmt) .. " round-trip: " .. tostring(r) .. " != " .. tostring(v))
      assert(pos == sz + 1, tostring(fmt) .. " pos: " .. tostring(pos))
    end
  end
end)
test("pack_compat: l/L/j/J/T bytes and unpack", function()
  local _list_0 = {
    "l",
    "j"
  }
  for _index_0 = 1, #_list_0 do
    local fmt = _list_0[_index_0]
    local got = pack(">" .. fmt, -1)
    local expected = from_hex("ffffffffffffffff")
    assert(got == expected, ">" .. tostring(fmt) .. " -1")
    local v, pos = unpack(">" .. fmt, got)
    assert(v == -1 and pos == 9, "unpack >" .. tostring(fmt) .. " -1 (got " .. tostring(v) .. ", " .. tostring(pos) .. ")")
  end
  local _list_1 = {
    "L",
    "J",
    "T"
  }
  for _index_0 = 1, #_list_1 do
    local fmt = _list_1[_index_0]
    local got = pack(">" .. fmt, 1)
    local expected = from_hex("0000000000000001")
    assert(got == expected, ">" .. tostring(fmt) .. " 1")
    local v, pos = unpack(">" .. fmt, got)
    assert(v == 1 and pos == 9, "unpack >" .. tostring(fmt) .. " 1 (got " .. tostring(v) .. ", " .. tostring(pos) .. ")")
  end
  return assert(pack("<L", 1) == from_hex("0100000000000000", "<L 1"))
end)
test("pack_compat: s1/s2/s4/s8 round-trip", function()
  local _list_0 = {
    1,
    2,
    4,
    8
  }
  for _index_0 = 1, #_list_0 do
    local sz = _list_0[_index_0]
    local _list_1 = {
      ">",
      "<"
    }
    for _index_1 = 1, #_list_1 do
      local prefix = _list_1[_index_1]
      local fmt = prefix .. "s" .. sz
      local got = pack(fmt, "ab")
      local r, pos = unpack(fmt, got)
      assert(r == "ab", tostring(fmt) .. " round-trip: " .. tostring(r))
      assert(pos == sz + 3, tostring(fmt) .. " pos: " .. tostring(pos))
    end
  end
  assert(pack(">s1", "ab") == from_hex("026162", ">s1"))
  assert(pack("<s4", "ab") == from_hex("020000006162", "<s4"))
  return assert(pack("s", "ab") == from_hex("02000000000000006162", "s default width and native order"))
end)
test("pack_compat: c1/c2/c0 and unpack", function()
  assert(pack("c1", "a") == "a", "c1")
  assert(pack("c2", "a") == from_hex("6100", "c2 pads"))
  local v, pos = unpack("c2", "abc")
  assert(v == "ab" and pos == 3, "unpack c2 (got " .. tostring(v) .. ", " .. tostring(pos) .. ")")
  v, pos = unpack("c0", "abc")
  return assert(v == "" and pos == 1, "unpack c0 (got '" .. tostring(v) .. "', " .. tostring(pos) .. ")")
end)
test("pack_compat: z round-trip and position", function()
  assert(pack("z", "") == from_hex("00", "z empty"))
  local v, pos = unpack("z", "hello\0")
  assert(v == "hello" and pos == 7, "unpack z (got " .. tostring(v) .. ", " .. tostring(pos) .. ")")
  local got = pack(">z B", "ab", 7)
  assert(got == from_hex("61620007", ">z B"))
  local a, b
  a, b, pos = unpack(">z B", got)
  return assert(a == "ab" and b == 7 and pos == 5, "unpack >z B (got " .. tostring(a) .. ", " .. tostring(b) .. ", " .. tostring(pos) .. ")")
end)
test("pack_compat: x unpack skips one byte", function()
  assert(pack("x") == from_hex("00", "x emits one NUL"))
  local pos = unpack("x", "\0")
  assert(pos == 2, "unpack x pos: " .. tostring(pos))
  local b
  b, pos = unpack("x B", "\0\7")
  return assert(b == 7 and pos == 3, "unpack x B (got " .. tostring(b) .. ", " .. tostring(pos) .. ")")
end)
test("pack_compat: endianness modifiers and alignment", function()
  assert(pack(">H", 1) == from_hex("0001", ">"))
  assert(pack("<H", 1) == from_hex("0100", "<"))
  assert(pack("=H", 1) == pack("<H", 1), "= follows native order")
  assert(pack(">!4H", 1) == from_hex("0001", "!4 alignment"))
  return assert(pack("! H", 1) == pack("<H", 1), "! without width")
end)
test("pack_compat: spaces in format", function()
  local got = pack(" > H  B ", 1, 2)
  assert(got == from_hex("000102", "spaces in format (got " .. tostring(got) .. ")"))
  local v, pos = unpack(" > H  B ", got)
  return assert(v == 1 and pos == 2, "unpack spaces (got " .. tostring(v) .. ", " .. tostring(pos) .. ")")
end)
local packsize = pack_compat.packsize or string.packsize
test("pack_compat: packsize fixed formats", function()
  assert(packsize("") == 0, "empty format")
  assert(packsize(">H B B H") == 6, ">H B B H")
  assert(packsize("i") == 4, "i default")
  assert(packsize("i3") == 3, "i3")
  assert(packsize("I5") == 5, "I5")
  assert(packsize("c10") == 10, "c10")
  assert(packsize("x") == 1, "x")
  assert(packsize(">H x H") == 5, ">H x H")
  assert(packsize("l") == 8, "l")
  assert(packsize("j") == 8, "j")
  assert(packsize("T") == 8, "T")
  return assert(packsize(">!4H") == 2, ">!4H")
end)
test("pack_compat: packsize rejects variable-size formats", function()
  local _list_0 = {
    "s",
    "z",
    "s2",
    ">H z"
  }
  for _index_0 = 1, #_list_0 do
    local opt = _list_0[_index_0]
    local ok = pcall(packsize, opt)
    assert(not ok, "packsize('" .. tostring(opt) .. "') should raise")
  end
end)
test("pack_compat: unpack short data raises for every option", function()
  local cases = {
    {
      "b",
      ""
    },
    {
      "B",
      ""
    },
    {
      "h",
      "\0"
    },
    {
      "H",
      "\0"
    },
    {
      "i2",
      "\0"
    },
    {
      "I2",
      "\0"
    },
    {
      "i8",
      "\0\0\0"
    },
    {
      "l",
      "\0\0"
    },
    {
      "L",
      "\0\0"
    },
    {
      "j",
      "\1"
    },
    {
      "J",
      "\1"
    },
    {
      "T",
      "\1"
    },
    {
      "s1",
      ""
    },
    {
      "s1",
      "\5ab"
    },
    {
      "c2",
      "a"
    },
    {
      "x",
      ""
    }
  }
  for _index_0 = 1, #cases do
    local item = cases[_index_0]
    local fmt, s = item[1], item[2]
    local ok, err = pcall(unpack, fmt, s, 1)
    assert(not ok, "unpack('" .. tostring(fmt) .. "') on short data should raise")
    assert((tostring(err):match("too short")), "unpack('" .. tostring(fmt) .. "'): expected 'data string too short', got: " .. tostring(tostring(err)))
  end
end)
test("pack_compat: unpack z without terminator raises", function()
  local ok, err = pcall(unpack, "z", "abc", 1)
  assert(not ok, "unpack('z') without NUL should raise")
  return assert((tostring(err):match("z")), "error should mention z, got: " .. tostring(tostring(err)))
end)
if is_fallback then
  test("pack_compat: pack writes more than 4096 bytes", function()
    local fmt = string.rep(">I8 ", 600)
    local values = { }
    for i = 1, 600 do
      values[i] = 1
    end
    local got = pack(fmt, tunpack(values))
    assert(#got == 4800, "expected 4800 bytes, got " .. tostring(#got))
    assert(got:sub(1, 8) == from_hex("0000000000000001", "first value corrupted"))
    return assert(got:sub(4793, 4800) == from_hex("0000000000000001", "last value corrupted"))
  end)
end
if is_fallback then
  test("pack_compat: inject sets string.pack/unpack/packsize", function()
    local saved_pack = string.pack
    local saved_unpack = string.unpack
    local saved_packsize = string.packsize
    local ok, err = pcall(function()
      pack_compat.inject()
      assert(string.pack == pack_compat.pack, "string.pack not injected")
      assert(string.unpack == pack_compat.unpack, "string.unpack not injected")
      assert(string.packsize == pack_compat.packsize, "string.packsize not injected")
      return assert(string.pack("B", 7) == from_hex("07", "injected pack wrong"))
    end)
    string.pack = saved_pack
    string.unpack = saved_unpack
    string.packsize = saved_packsize
    return assert(ok, err)
  end)
end
return util.summary("pack_compat")
