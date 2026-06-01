local ffi = require("ffi")
local TWO48 = 0x1000000000000ULL
local truncate
truncate = function(h)
  return h % TWO48
end
local pack
pack = function(hashes, n)
  local buf = ffi.new("uint8_t[?]", n * 6)
  for i = 1, n do
    local v = hashes[i]
    local base = (i - 1) * 6
    for k = 0, 5 do
      buf[base + k] = tonumber(v % 256ULL)
      v = v / 256ULL
    end
  end
  return ffi.string(buf, n * 6)
end
local rec_at_bytewise
rec_at_bytewise = function(arr8, i)
  local b = arr8 + i * 6
  local v = 0ULL
  for k = 5, 0, -1 do
    v = v * 256ULL + b[k]
  end
  return v
end
local TWO32 = 0x100000000ULL
local _u32 = ffi.typeof("const uint32_t*")
local _u16 = ffi.typeof("const uint16_t*")
local rec_at_unaligned
rec_at_unaligned = function(arr8, i)
  local b = arr8 + i * 6
  return ffi.cast("uint64_t", (ffi.cast(_u32, b))[0]) + ffi.cast("uint64_t", (ffi.cast(_u16, b + 4))[0]) * TWO32
end
local _arch = (require("jit")).arch
local _unaligned_ok = {
  x86 = true,
  x64 = true,
  arm = true,
  arm64 = true,
  ppc = true
}
local rec_at = _unaligned_ok[_arch] and rec_at_unaligned or rec_at_bytewise
local pack_domains
pack_domains = function(domains)
  local xxhash = require("ffi_xxhash")
  local seen, h, n = { }, { }, 0
  for _index_0 = 1, #domains do
    local _continue_0 = false
    repeat
      local d = domains[_index_0]
      if seen[d] then
        _continue_0 = true
        break
      end
      seen[d] = true
      n = n + 1
      h[n] = truncate(xxhash.xxh64(d))
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  if n == 0 then
    return "", 0
  end
  table.sort(h, function(a, b)
    return a < b
  end)
  return (pack(h, n)), n
end
local bsearch
bsearch = function(arr8, n, target)
  local lo, hi = 0, n - 1
  while lo <= hi do
    local mid = math.floor((lo + hi) * 0.5)
    local v = rec_at(arr8, mid)
    if v == target then
      return true
    elseif v < target then
      lo = mid + 1
    else
      hi = mid - 1
    end
  end
  return false
end
return {
  truncate = truncate,
  pack = pack,
  pack_domains = pack_domains,
  rec_at = rec_at,
  rec_at_bytewise = rec_at_bytewise,
  rec_at_unaligned = rec_at_unaligned,
  bsearch = bsearch,
  TWO48 = TWO48
}
