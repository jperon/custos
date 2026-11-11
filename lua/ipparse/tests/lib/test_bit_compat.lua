local util = require("ipparse.lib.util")
local test
test = util.test
local band, bor, bxor, arshift
do
  local _obj_0 = require("ipparse.lib.bit_compat")
  band, bor, bxor, arshift = _obj_0.band, _obj_0.bor, _obj_0.bxor, _obj_0.arshift
end
local pure = require("ipparse.lib.bit_pure")
local test_pure
test_pure = function(name, fn)
  if math.floor then
    return test(name, fn)
  end
end
test("bit_compat: band with 1 argument", function()
  return assert(band(5) == 5, "band(5) != 5")
end)
test("bit_compat: band with 7 arguments", function()
  return assert(band(0xFF, 0xFF, 0xFF, 0x3C, 0xFF, 0x1E, 0xFF) == 28, "band of 7 arguments != 28")
end)
test("bit_compat: bxor with 1 argument", function()
  return assert(bxor(5) == 5, "bxor(5) != 5")
end)
test("bit_compat: bxor with 7 arguments", function()
  return assert(bxor(0xFF, 0x0F, 0xF0, 0x3C, 0xC3, 0x55, 0xAA) == 0, "bxor of 7 arguments != 0")
end)
test("bit_compat: bor with 1 argument", function()
  return assert(bor(5) == 5, "bor(5) != 5")
end)
test("bit_compat: bor with 2 arguments", function()
  return assert(bor(1, 2) == 3, "bor(1,2) != 3")
end)
test("bit_compat: bor with 7 arguments", function()
  return assert(bor(1, 2, 4, 8, 16, 32, 64) == 127, "bor(1,2,4,8,16,32,64) != 127")
end)
test("bit_compat: bor with 7 TCP flag arguments", function()
  return assert(bor(0, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01) == 63, "TCP flags != 63")
end)
test("bit_compat: band with 3 arguments", function()
  return assert(band(0xFF, 0x3C, 0x1E) == 28, "band(0xFF,0x3C,0x1E) != 28")
end)
test("bit_compat: bxor with 3 arguments", function()
  return assert(bxor(0xF0, 0x3C, 0xFF) == 51, "bxor(0xF0,0x3C,0xFF) != 51")
end)
test("bit_compat: arshift sign-extends", function()
  assert(arshift(-8, 1) == -4, "arshift(-8,1) != -4")
  return assert(arshift(8, 1) == 4, "arshift(8,1) != 4")
end)
test_pure("bit_pure: band with 1 argument", function()
  return assert(pure.band(0xFF) == 255, "band(0xFF) != 255")
end)
test_pure("bit_pure: band with 2 arguments", function()
  assert(pure.band(-1, 0xFF) == 255, "band(-1,0xFF) != 255")
  assert(pure.band(0xFFFFFFFF, 0xFFFF) == 65535, "band(0xFFFFFFFF,0xFFFF) != 65535")
  return assert(pure.band(0x80000000, 0x80000000) == -2147483648, "band of bit 31 != -2147483648")
end)
test_pure("bit_pure: band with 3 arguments", function()
  return assert(pure.band(0xFF, 0x3C, 0x1E) == 28, "band(0xFF,0x3C,0x1E) != 28")
end)
test_pure("bit_pure: bor with 1 argument", function()
  assert(pure.bor(5) == 5, "bor(5) != 5")
  return assert(pure.bor(0x80000000) == -2147483648, "bor(0x80000000) != -2147483648")
end)
test_pure("bit_pure: bor with 2 arguments", function()
  assert(pure.bor(1, 2) == 3, "bor(1,2) != 3")
  assert(pure.bor(0x80000000, 0) == -2147483648, "bor(0x80000000,0) != -2147483648")
  return assert(pure.bor(0x80000000, 0xFF) == -2147483393, "bor(0x80000000,0xFF) != -2147483393")
end)
test_pure("bit_pure: bor with 3 arguments", function()
  return assert(pure.bor(1, 2, 4) == 7, "bor(1,2,4) != 7")
end)
test_pure("bit_pure: bor with 7 arguments", function()
  return assert(pure.bor(1, 2, 4, 8, 16, 32, 64) == 127, "bor(1,2,4,8,16,32,64) != 127")
end)
test_pure("bit_pure: bxor with 1 argument", function()
  return assert(pure.bxor(5) == 5, "bxor(5) != 5")
end)
test_pure("bit_pure: bxor with 2 arguments", function()
  assert(pure.bxor(0x80000000, 0xFFFFFFFF) == 2147483647, "bxor(0x80000000,0xFFFFFFFF) != 2147483647")
  assert(pure.bxor(0x80000000, 0x80000000) == 0, "bxor(0x80000000,0x80000000) != 0")
  return assert(pure.bxor(-1, 0xFF) == -256, "bxor(-1,0xFF) != -256")
end)
test_pure("bit_pure: bxor with 3 arguments", function()
  return assert(pure.bxor(0xF0, 0x3C, 0xFF) == 51, "bxor(0xF0,0x3C,0xFF) != 51")
end)
test_pure("bit_pure: bnot", function()
  assert(pure.bnot(0) == -1, "bnot(0) != -1")
  assert(pure.bnot(0xFFFFFFFF) == 0, "bnot(0xFFFFFFFF) != 0")
  return assert(pure.bnot(-1) == 0, "bnot(-1) != 0")
end)
test_pure("bit_pure: lshift by 0, 1 and 31 bits", function()
  assert(pure.lshift(3, 0) == 3, "lshift(3,0) != 3")
  assert(pure.lshift(1, 1) == 2, "lshift(1,1) != 2")
  return assert(pure.lshift(1, 31) == -2147483648, "lshift(1,31) != -2147483648")
end)
test_pure("bit_pure: lshift masks the shift count to 5 bits", function()
  assert(pure.lshift(1, 32) == 1, "lshift(1,32) != 1")
  return assert(pure.lshift(1, 33) == 2, "lshift(1,33) != 2")
end)
test_pure("bit_pure: rshift by 0, 1 and 31 bits", function()
  assert(pure.rshift(3, 0) == 3, "rshift(3,0) != 3")
  assert(pure.rshift(0x80000000, 1) == 1073741824, "rshift(0x80000000,1) != 1073741824")
  assert(pure.rshift(0x80000000, 31) == 1, "rshift(0x80000000,31) != 1")
  assert(pure.rshift(-1, 1) == 2147483647, "rshift(-1,1) != 2147483647")
  return assert(pure.rshift(0x80000000, 32) == -2147483648, "rshift(0x80000000,32) != -2147483648")
end)
test_pure("bit_pure: arshift sign-extends", function()
  assert(pure.arshift(3, 0) == 3, "arshift(3,0) != 3")
  assert(pure.arshift(0x80000000, 1) == -1073741824, "arshift(0x80000000,1) != -1073741824")
  assert(pure.arshift(-1, 1) == -1, "arshift(-1,1) != -1")
  return assert(pure.arshift(0x40000000, 1) == 536870912, "arshift(0x40000000,1) != 536870912")
end)
test_pure("bit_pure: IPv6 version/traffic class/flow label round-trip", function()
  local vtf = pure.bor(pure.lshift(6, 28), pure.lshift(0x12, 20), 0x34567)
  assert(vtf == 1629701479, "vtf != 1629701479")
  assert(pure.rshift(vtf, 28) == 6, "version != 6")
  assert(pure.band(pure.rshift(vtf, 20), 0xFF) == 18, "traffic class != 18")
  return assert(pure.band(vtf, 0xFFFFF) == 214375, "flow label != 214375")
end)
local native_int = math.floor == nil or math.type ~= nil
local backend_keys = {
  "bit",
  "bit32",
  "ipparse.lib.bit53",
  "ipparse.lib.bit_pure",
  "ipparse.lib.bit_compat"
}
local load_bit_compat_with
load_bit_compat_with = function(preloads)
  local saved_loaded = { }
  local saved_preload = { }
  for _index_0 = 1, #backend_keys do
    local k = backend_keys[_index_0]
    saved_loaded[k] = package.loaded[k]
    saved_preload[k] = package.preload[k]
  end
  local mod = nil
  local ok = false
  local err = nil
  ok, err = pcall(function()
    for _index_0 = 1, #backend_keys do
      local k = backend_keys[_index_0]
      package.loaded[k] = nil
      package.preload[k] = nil
    end
    for k, v in pairs(preloads) do
      if type(v) == "function" then
        package.preload[k] = v
      else
        package.preload[k] = function()
          return v
        end
      end
    end
    mod = require("ipparse.lib.bit_compat")
  end)
  for _index_0 = 1, #backend_keys do
    local k = backend_keys[_index_0]
    package.loaded[k] = saved_loaded[k]
    package.preload[k] = saved_preload[k]
  end
  if not (ok) then
    error(err, 0)
  end
  return mod
end
local pow2_test
pow2_test = function(n)
  local p = 1
  for _ = 1, n do
    p = p * 2
  end
  return p
end
local fake_named = {
  blshift = function(a, n)
    if n <= 0 then
      return a
    else
      return a * pow2_test(n)
    end
  end,
  brshift = function(a, n)
    if n <= 0 then
      return a
    else
      return math.floor(a / pow2_test(n))
    end
  end
}
local fake32 = {
  blshift = function(a, n)
    return 111
  end,
  brshift = function(a, n)
    return 222
  end
}
local fake_pure = {
  blshift = function(a, n)
    return 555
  end,
  brshift = function(a, n)
    return 666
  end
}
local bad_backend
bad_backend = function()
  return error("backend unavailable")
end
local userspace_backends = package and package.loaded and package.preload and math.floor
local test_backends
test_backends = function(name, fn)
  if userspace_backends and not native_int then
    return test(name, fn)
  end
end
local test_native_backends
test_native_backends = function(name, fn)
  if userspace_backends and native_int then
    return test(name, fn)
  end
end
test_backends("bit_compat: fallback shifts when 'bit' lacks shifts", function()
  local m = load_bit_compat_with({
    ["bit"] = { }
  })
  assert(m.lshift(3, 2) == 12, "lshift(3,2) != 12")
  assert(m.lshift(3, 0) == 3, "lshift by 0 must be identity")
  assert(m.lshift(3, -2) == 3, "lshift by a negative count must be identity")
  assert(m.rshift(8, 2) == 2, "rshift(8,2) != 2")
  assert(m.rshift(8, 0) == 8, "rshift by 0 must be identity")
  assert(m.rshift(8, -1) == 8, "rshift by a negative count must be identity")
  assert(m.rshift(0x100000004, 2) == 1, "rshift must mask its input to 32 bits")
  assert(m.arshift == m.rshift, "arshift should alias rshift")
  return assert(m.lshift(1, 4) == 16, "lshift(1,4) != 16")
end)
test_backends("bit_compat: blshift/brshift preferred over fallback", function()
  local m = load_bit_compat_with({
    ["bit"] = fake_named
  })
  assert(m.lshift(2, 3) == 16, "lshift(2,3) != 16")
  assert(m.rshift(32, 3) == 4, "rshift(32,3) != 4")
  return assert(m.arshift == m.rshift, "arshift should alias rshift")
end)
test_backends("bit_compat: bit32 backend selection", function()
  local m = load_bit_compat_with({
    ["bit32"] = fake32
  })
  assert(m.lshift(1, 1) == 111, "bit32 backend not selected for lshift")
  assert(m.rshift(1, 1) == 222, "bit32 backend not selected for rshift")
  return assert(m.arshift == m.rshift, "arshift should alias rshift")
end)
test_native_backends("bit_compat: native backend preferred over a fake 'bit'", function()
  local real53 = require("ipparse.lib.bit53")
  local saved_loaded = package.loaded["bit"]
  local saved_preload = package.preload["bit"]
  local saved_compat = package.loaded["ipparse.lib.bit_compat"]
  local m = nil
  local ok, err = pcall(function()
    package.loaded["bit"] = nil
    package.preload["bit"] = function()
      return {
        lshift = function(a, n)
          return 999
        end,
        rshift = function(a, n)
          return 999
        end
      }
    end
    package.loaded["ipparse.lib.bit_compat"] = nil
    m = require("ipparse.lib.bit_compat")
  end)
  package.loaded["bit"] = saved_loaded
  package.preload["bit"] = saved_preload
  package.loaded["ipparse.lib.bit_compat"] = saved_compat
  if not (ok) then
    error(err, 0)
  end
  assert(m == real53, "native bit53 backend not selected over a fake 'bit'")
  return assert(m.band(0xFFFFFFFF, 0xFFFFFFFFFF) == 0xFFFFFFFF, "native band must cover 64 bits")
end)
test_native_backends("bit_compat: bit53 load error propagates", function()
  local saved_loaded = package.loaded["ipparse.lib.bit53"]
  local saved_preload = package.preload["ipparse.lib.bit53"]
  local saved_compat = package.loaded["ipparse.lib.bit_compat"]
  local ok = false
  local err = nil
  ok, err = pcall(function()
    package.loaded["ipparse.lib.bit53"] = nil
    package.preload["ipparse.lib.bit53"] = function()
      return error("boom-stack")
    end
    package.loaded["ipparse.lib.bit_compat"] = nil
    return require("ipparse.lib.bit_compat")
  end)
  package.loaded["ipparse.lib.bit53"] = saved_loaded
  package.preload["ipparse.lib.bit53"] = saved_preload
  package.loaded["ipparse.lib.bit_compat"] = saved_compat
  assert(not ok, "loading bit_compat must fail when bit53 fails")
  assert((tostring(err):find("boom-stack", 1, true)), "expected the bit53 error, got: " .. tostring(tostring(err)))
  return assert(not (tostring(err):find("no bitwise compatibility backend", 1, true)), "generic error masked the bit53 failure: " .. tostring(tostring(err)))
end)
test_backends("bit_compat: bit53 ignored without native integers", function()
  local ok, err = pcall(load_bit_compat_with, {
    ["bit"] = bad_backend,
    ["bit32"] = bad_backend,
    ["ipparse.lib.bit53"] = {
      lshift = function(a, n)
        return 777
      end,
      rshift = function(a, n)
        return 888
      end
    },
    ["ipparse.lib.bit_pure"] = bad_backend
  })
  assert(not ok, "bit53 must not be consulted on a non-native-integer runtime")
  return assert((tostring(err):match("no bitwise compatibility backend")), "unexpected error: " .. tostring(tostring(err)))
end)
test_backends("bit_compat: bit_pure last-resort backend selection", function()
  local m = load_bit_compat_with({
    ["bit"] = bad_backend,
    ["bit32"] = bad_backend,
    ["ipparse.lib.bit53"] = bad_backend,
    ["ipparse.lib.bit_pure"] = fake_pure
  })
  assert(m.lshift(1, 1) == 555, "bit_pure backend not selected for lshift")
  return assert(m.rshift(1, 1) == 666, "bit_pure backend not selected for rshift")
end)
test_backends("bit_compat: no backend raises", function()
  local ok, err = pcall(load_bit_compat_with, {
    ["bit"] = bad_backend,
    ["bit32"] = bad_backend,
    ["ipparse.lib.bit53"] = bad_backend,
    ["ipparse.lib.bit_pure"] = bad_backend
  })
  assert(not ok, "loading with no backend should raise")
  return assert((tostring(err):match("no bitwise compatibility backend")), "unexpected error: " .. tostring(tostring(err)))
end)
return util.summary("bit_compat")
