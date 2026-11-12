local hex2bin
hex2bin = require("ipparse.init").hex2bin
local dns = require("ipparse.l7.dns")
local ip4 = require("ipparse.l3.ip4")
local udp = require("ipparse.l4.udp")
local checksum
checksum = require("ipparse.l3.lib").checksum
local sp, su
do
  local _obj_0 = require("ipparse.lib.pack_compat")
  sp, su = _obj_0.pack, _obj_0.unpack
end
local new_ip
new_ip = require("ipparse.l3.ip").new
local new_udp
new_udp = require("ipparse.l4.udp").new
local os_clock = os.clock
local env_num
env_num = function(name, d)
  local v = os.getenv(name)
  return (v and tonumber(v)) or d
end
local ITERS = env_num("BENCH_ITERS", 300000)
local REPEATS = env_num("BENCH_REPEATS", 5)
local WARMUP = env_num("BENCH_WARMUP", 5000)
local ALLOC_ITERS = env_num("BENCH_ALLOC_ITERS", 2000)
local ONLY = os.getenv("BENCH_ONLY")
local OUT_PATH = os.getenv("BENCH_OUT")
local BASE_PATH = os.getenv("BENCH_BASELINE")
local SRC4 = "\10\35\1\2"
local DST4 = "\10\35\1\1"
local SRC6 = "\252\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1"
local QNAME_HEX = "0b636f6e74726f6c70616e65" .. "056c6f67696e" .. "097461696c7363616c65" .. "03636f6d" .. "00"
local QUERY_HEX = "123401000001000000000000" .. QNAME_HEX .. "00010001"
local RESP8_HEX = "123481800001000800000000" .. QNAME_HEX .. "00010001"
for i = 1, 8 do
  RESP8_HEX = RESP8_HEX .. "c00c00010001" .. "0000012c" .. "0004" .. "6440000" .. tostring(i)
end
local CNAME_HEX = "123481800001000200000000" .. "03777777076578616d706c6503636f6d00" .. "00010001" .. "c00c" .. "00050001" .. "0000012c" .. "0012" .. "076578616d706c6503636f6d00" .. "c01e" .. "00010001" .. "0000012c" .. "0004" .. "5db8d822"
local query = hex2bin(QUERY_HEX)
local resp8 = hex2bin(RESP8_HEX)
local resp_c = hex2bin(CNAME_HEX)
local udp_pkt = hex2bin((QNAME_HEX .. "00010001"))
local hdr20 = sp(">BBHHHBBH c4c4", 0x45, 0, 40, 1, 0x4000, 64, 17, 0, SRC4, DST4)
local pkt = tostring(new_ip({
  version = 4,
  v_ihl = 0x45,
  tos = 0,
  id = 1,
  ff = 0x4000,
  ttl = 64,
  protocol = 17,
  src = SRC4,
  dst = DST4,
  options = "",
  data = new_udp({
    spt = 5353,
    dpt = 53,
    checksum = 0,
    data = udp_pkt
  })
}))
local RR_OFF = 12 + #QNAME_HEX / 2 + 4 + 1
local CSUM_IN = sp(">c4c4 x B s2", SRC4, DST4, 17, udp_pkt) .. udp_pkt
local ip_pkt_obj = new_ip({
  version = 4,
  v_ihl = 0x45,
  tos = 0,
  id = 1,
  ff = 0x4000,
  ttl = 64,
  protocol = 17,
  src = SRC4,
  dst = DST4,
  options = "",
  data = new_udp({
    spt = 5353,
    dpt = 53,
    checksum = 0,
    data = udp_pkt
  })
})
local cases = {
  {
    "dns_parse_query",
    function()
      return dns.parse(query, 1, false)
    end
  },
  {
    "dns_parse_resp8",
    function()
      return dns.parse(resp8, 1, false)
    end
  },
  {
    "dns_parse_resp_cname",
    function()
      return dns.parse(resp_c, 1, false)
    end
  },
  {
    "dns_parse_header",
    function()
      return dns.parse_header(resp8, 1, false)
    end
  },
  {
    "dns_parse_question",
    function()
      return dns.parse_question(resp8, 13, 1)
    end
  },
  {
    "dns_parse_rr",
    function()
      return dns.parse_rr(resp8, RR_OFF, 1)
    end
  },
  {
    "dns_labels",
    function()
      return dns.labels(resp8, 13, 1)
    end
  },
  {
    "ip4_parse",
    function()
      return ip4.parse(pkt, 1)
    end
  },
  {
    "udp_parse",
    function()
      return udp.parse(pkt, 21)
    end
  },
  {
    "sp_ip4hdr",
    function()
      return sp(">BBHHHBBH c4c4", 0x45, 0, 40, 1, 0x4000, 64, 17, 0, SRC4, DST4)
    end
  },
  {
    "sp_pseudo",
    function()
      return sp(">c4c4 x B s2", SRC4, DST4, 17, udp_pkt)
    end
  },
  {
    "sp_udp",
    function()
      return sp(">H H H H", 5353, 53, 40, 0)
    end
  },
  {
    "sp_dns_header",
    function()
      return sp(">H B B H H H H", 0x1234, 0x8180, 0, 1, 8, 0, 0)
    end
  },
  {
    "su_ip4hdr",
    function()
      return su(">BBHHHBBH c4c4", pkt, 1)
    end
  },
  {
    "su_dns_header",
    function()
      return su(">H B B H H H H", resp8, 1)
    end
  },
  {
    "su_rr",
    function()
      return su(">H H I4 H", resp8, RR_OFF)
    end
  },
  {
    "checksum_20",
    function()
      return checksum(hdr20)
    end
  },
  {
    "checksum_udp",
    function()
      return checksum(CSUM_IN)
    end
  },
  {
    "ip4_pack_udp",
    function()
      return tostring(ip_pkt_obj)
    end
  }
}
local measure
measure = function(fn)
  for i = 1, WARMUP do
    fn()
  end
  local best = math.huge
  for r = 1, REPEATS do
    local t0 = os_clock()
    for i = 1, ITERS do
      fn()
    end
    local dt = os_clock() - t0
    if dt < best then
      best = dt
    end
  end
  collectgarbage("collect")
  collectgarbage("stop")
  local b0 = collectgarbage("count")
  for i = 1, ALLOC_ITERS do
    fn()
  end
  local b1 = collectgarbage("count")
  collectgarbage("restart")
  collectgarbage("collect")
  return best / ITERS * 1e6, (b1 - b0) * 1024 / ALLOC_ITERS
end
local load_baseline
load_baseline = function(path)
  local base = { }
  local f = io.open(path, "r")
  if not (f) then
    return base
  end
  for line in f:lines() do
    local name, us, bytes = line:match("^(%S+)%s+(%S+)%s+(%S+)$")
    if name then
      base[name] = {
        us = tonumber(us),
        bytes = tonumber(bytes)
      }
    end
  end
  f:close()
  return base
end
local pct
pct = function(now, before)
  if not (before and before > 0) then
    return ""
  end
  local d = (now - before) / before * 100
  return ("%+.1f%%"):format(d)
end
local results = { }
for _index_0 = 1, #cases do
  local _continue_0 = false
  repeat
    local c = cases[_index_0]
    local name, fn = c[1], c[2]
    if ONLY and not name:find(ONLY, 1, true) then
      _continue_0 = true
      break
    end
    local us, bytes = measure(fn)
    results[#results + 1] = {
      name = name,
      us = us,
      bytes = bytes
    }
    _continue_0 = true
  until true
  if not _continue_0 then
    break
  end
end
local base
if BASE_PATH then
  base = load_baseline(BASE_PATH)
else
  base = { }
end
if OUT_PATH then
  local f = io.open(OUT_PATH, "w")
  if f then
    for _index_0 = 1, #results do
      local r = results[_index_0]
      f:write((tostring(r.name) .. "\t" .. tostring(r.us) .. "\t" .. tostring(r.bytes) .. "\n"))
    end
    f:close()
  end
end
local jit_info
if type(jit) == "table" then
  jit_info = tostring(jit.version) .. " / " .. tostring(jit.arch)
else
  jit_info = "non-LuaJIT (_VERSION=" .. tostring(_VERSION) .. ")"
end
print("# Micro-banc ipparse — chemins chauds")
print("")
print("- " .. tostring(jit_info))
print("- iters=" .. tostring(ITERS) .. ", repeat=" .. tostring(REPEATS) .. " (minimum retenu), warmup=" .. tostring(WARMUP) .. ", alloc_iters=" .. tostring(ALLOC_ITERS))
if BASE_PATH then
  print("- baseline : " .. tostring(BASE_PATH))
end
print("")
print("| cas | µs/appel | Δ baseline | o/appel | Δ baseline |")
print("|---|---|---|---|---|")
for _index_0 = 1, #results do
  local r = results[_index_0]
  local b = base[r.name]
  local row = ("| " .. tostring(r.name) .. " | %.4f | %s | %.0f | %s |"):format(r.us, pct(r.us, b and b.us), r.bytes, pct(r.bytes, b and b.bytes))
  print(row)
end
if OUT_PATH then
  return print("\n(mesures écrites : " .. tostring(OUT_PATH) .. ")")
end
