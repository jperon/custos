local util = require("ipparse.lib.util")
local test
test = util.test
local pack_compat = require("ipparse.lib.pack_compat")
local pack = pack_compat.pack or string.pack
local unpack = pack_compat.unpack or string.unpack
local from_hex
from_hex = function(h)
  local out = h:gsub("..", function(cc)
    return string.char(tonumber(cc, 16))
  end)
  return out
end
test("pack_compat_float: <d 1.5 bytes", function()
  local got = pack("<d", 1.5)
  local expected = from_hex("000000000000f83f")
  return assert(got == expected, "got: " .. tostring(got) .. "\nexp: " .. tostring(expected))
end)
test("pack_compat_float: >d -2.5 bytes", function()
  local got = pack(">d", -2.5)
  local expected = from_hex("c004000000000000")
  return assert(got == expected, "got: " .. tostring(got) .. "\nexp: " .. tostring(expected))
end)
test("pack_compat_float: <f 1.5 bytes", function()
  local got = pack("<f", 1.5)
  local expected = from_hex("0000c03f")
  return assert(got == expected, "got: " .. tostring(got) .. "\nexp: " .. tostring(expected))
end)
test("pack_compat_float: <d round-trip", function()
  local v, pos = unpack("<d", pack("<d", -123.456))
  assert(v == -123.456, "got: " .. tostring(v))
  return assert(pos == 9, "pos: " .. tostring(pos))
end)
test("pack_compat_float: >d round-trip", function()
  local v, pos = unpack(">d", pack(">d", 123.456))
  assert(v == 123.456, "got: " .. tostring(v))
  return assert(pos == 9, "pos: " .. tostring(pos))
end)
test("pack_compat_float: <f round-trip", function()
  local v, pos = unpack("<f", pack("<f", -2.25))
  assert(v == -2.25, "got: " .. tostring(v))
  return assert(pos == 5, "pos: " .. tostring(pos))
end)
test("pack_compat_float: <d infinities", function()
  assert(unpack("<d", pack("<d", math.huge)) == math.huge)
  return assert(unpack("<d", pack("<d", -math.huge)) == -math.huge)
end)
test("pack_compat_float: <d signed zero", function()
  local got = pack("<d", -0.0)
  local expected = from_hex("0000000000000080")
  assert(got == expected, "got: " .. tostring(got) .. "\nexp: " .. tostring(expected))
  local v = unpack("<d", got)
  return assert(v == 0 and 1 / v < 0, "lost negative zero")
end)
test("pack_compat_float: <d smallest subnormal", function()
  local v = 2 ^ -1074
  local got = pack("<d", v)
  local expected = from_hex("0100000000000000")
  assert(got == expected, "got: " .. tostring(got) .. "\nexp: " .. tostring(expected))
  return assert(unpack("<d", got) == v, "subnormal round-trip")
end)
test("pack_compat_float: <d nan", function()
  local nan = math.huge - math.huge
  local v = unpack("<d", pack("<d", nan))
  return assert(v ~= v, "expected NaN, got: " .. tostring(v))
end)
test("pack_compat_float: >f bytes and unpack", function()
  local got = pack(">f", -2.25)
  local expected = from_hex("c0100000")
  assert(got == expected, "got: " .. tostring(got) .. "\nexp: " .. tostring(expected))
  local v, pos = unpack(">f", got)
  return assert(v == -2.25 and pos == 5, "got: " .. tostring(v) .. ", pos: " .. tostring(pos))
end)
test("pack_compat_float: n matches d", function()
  local _list_0 = {
    ">",
    "<"
  }
  for _index_0 = 1, #_list_0 do
    local prefix = _list_0[_index_0]
    local _list_1 = {
      1.5,
      -2.5,
      0.0
    }
    for _index_1 = 1, #_list_1 do
      local v = _list_1[_index_1]
      assert(pack(prefix .. "n", v) == pack(prefix .. "d", v), tostring(prefix) .. "n differs from " .. tostring(prefix) .. "d for " .. tostring(v))
      local r, pos = unpack(prefix .. "n", pack(prefix .. "n", v))
      assert(r == v and pos == 9, tostring(prefix) .. "n round-trip: " .. tostring(r) .. ", " .. tostring(pos))
    end
  end
end)
test("pack_compat_float: d/f in the middle of a format", function()
  local got = pack(">H d B", 1, 1.5, 2)
  local expected = from_hex("0001") .. from_hex("3ff8000000000000") .. from_hex("02")
  assert(got == expected, "got: " .. tostring(got) .. "\nexp: " .. tostring(expected))
  local a, b, c, pos = unpack(">H d B", got)
  return assert(a == 1 and b == 1.5 and c == 2 and pos == 12, "got: " .. tostring(a) .. ", " .. tostring(b) .. ", " .. tostring(c) .. ", pos: " .. tostring(pos))
end)
test("pack_compat_float: unpack short f/d/n raises", function()
  local cases = {
    {
      "f",
      from_hex("0000")
    },
    {
      "d",
      from_hex("00000000000000")
    },
    {
      "n",
      from_hex("00000000000000")
    },
    {
      ">f",
      from_hex("c01000")
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
test("pack_compat_float: packsize f/d/n", function()
  local packsize = pack_compat.packsize or string.packsize
  assert(packsize("f") == 4, "f")
  assert(packsize("d") == 8, "d")
  assert(packsize("n") == 8, "n")
  assert(packsize(">H f d") == 14, ">H f d")
  return assert(packsize(">H d B") == 11, ">H d B")
end)
return util.summary("pack_compat_float")
