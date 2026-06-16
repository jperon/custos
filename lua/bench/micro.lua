local ffi = require("ffi")
local bench
bench = function(name, iters, fn)
  collectgarbage("collect")
  local m0 = collectgarbage("count")
  local t0 = os.clock()
  fn(iters)
  local t1 = os.clock()
  local m1 = collectgarbage("count")
  return {
    name = name,
    ns_per_op = (t1 - t0) / iters * 1e9,
    kb_alloc = m1 - m0
  }
end
local _sample_raw
do
  local hex = "4500003a0000400040113c90c0a80101c0a80102" .. "80d9003500260000" .. "12340100000100000000000006676f6f676c6503636f6d0000010001"
  _sample_raw = (hex:gsub("..", function(cc)
    return string.char(tonumber(cc, 16))
  end))
end
local _standard_cases = {
  {
    name = "ipparse ip4+udp+dns parse",
    setup = function()
      local parse_ip4
      parse_ip4 = require("ipparse.l3.ip4").parse
      local parse_udp
      parse_udp = require("ipparse.l4.udp").parse
      local parse_dns
      parse_dns = require("ipparse.l7.dns").parse
      local raw = _sample_raw
      return function(n)
        for _ = 1, n do
          local off
          _, off = parse_ip4(raw)
          local off2
          _, off2 = parse_udp(raw, off)
          parse_dns(raw, off2, false)
        end
      end
    end
  },
  {
    name = "bin48 truncate",
    setup = function()
      local truncate
      truncate = require("filter.lib.bin48").truncate
      local h = 0x123456789abcdefULL
      return function(n)
        for _ = 1, n do
          truncate(h)
        end
      end
    end
  },
  {
    name = "xxhash xxh64 (domaine)",
    setup = function()
      local xxh64
      xxh64 = require("ffi_xxhash").xxh64
      local s = "www.example.com"
      return function(n)
        for _ = 1, n do
          xxh64(s)
        end
      end
    end
  }
}
local run
run = function(opts)
  if opts == nil then
    opts = { }
  end
  local iters = opts.iters or 1e6
  local cases
  do
    local _accum_0 = { }
    local _len_0 = 1
    for _index_0 = 1, #_standard_cases do
      local c = _standard_cases[_index_0]
      _accum_0[_len_0] = c
      _len_0 = _len_0 + 1
    end
    cases = _accum_0
  end
  if opts.extra_cases then
    local _list_0 = opts.extra_cases
    for _index_0 = 1, #_list_0 do
      local c = _list_0[_index_0]
      cases[#cases + 1] = c
    end
  end
  local results = { }
  for _index_0 = 1, #cases do
    local c = cases[_index_0]
    local ok, fn_or_err = pcall(c.setup)
    if ok and type(fn_or_err) == "function" then
      results[#results + 1] = bench(c.name, iters, fn_or_err)
    else
      results[#results + 1] = {
        name = c.name,
        ns_per_op = 0,
        kb_alloc = 0,
        skipped = true,
        reason = tostring(fn_or_err)
      }
    end
  end
  return results
end
return {
  bench = bench,
  run = run
}
