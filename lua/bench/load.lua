local ffi = require("ffi")
local report = require("bench.report")
local floor = math.floor
local char = string.char
local concat = table.concat
local _now
do
  local ok = pcall(ffi.cdef, [[    struct bench_timeval { long tv_sec; long tv_usec; };
    int gettimeofday(struct bench_timeval *tv, void *tz);
  ]])
  if ok then
    local tv = ffi.new("struct bench_timeval")
    _now = function()
      ffi.C.gettimeofday(tv, nil)
      return tonumber(tv.tv_sec) + tonumber(tv.tv_usec) / 1e6
    end
  else
    _now = function()
      return os.clock()
    end
  end
end
local encode_query
encode_query = function(txid, qname, qtype)
  if qtype == nil then
    qtype = 1
  end
  local parts = { }
  local hi = floor(txid / 256)
  local lo = txid % 256
  parts[#parts + 1] = char(hi, lo, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
  for label in qname:gmatch("[^.]+") do
    parts[#parts + 1] = char(#label)
    parts[#parts + 1] = label
  end
  parts[#parts + 1] = char(0)
  parts[#parts + 1] = char(floor(qtype / 256), qtype % 256, 0x00, 0x01)
  return concat(parts)
end
local _real_client_factory
_real_client_factory = function(target, port, timeout_ms)
  if timeout_ms == nil then
    timeout_ms = 2000
  end
  return function()
    local sock = require("lib.socket")
    local C, AF_INET, AF_INET6, SOCK_DGRAM, htons
    C, AF_INET, AF_INET6, SOCK_DGRAM, htons = sock.C, sock.AF_INET, sock.AF_INET6, sock.SOCK_DGRAM, sock.htons
    local is_v6 = target:find(":") ~= nil
    local family = is_v6 and AF_INET6 or AF_INET
    local fd = C.socket(family, SOCK_DGRAM, 0)
    if fd < 0 then
      error("socket() failed")
    end
    if is_v6 then
      local addr = ffi.new("struct sockaddr_in6")
      addr.sin6_family = AF_INET6
      addr.sin6_port = htons(port)
      C.inet_pton(AF_INET6, target, addr.sin6_addr)
      C.connect(fd, ffi.cast("struct sockaddr*", addr), ffi.sizeof(addr))
    else
      local addr = ffi.new("struct sockaddr_in")
      addr.sin_family = AF_INET
      addr.sin_port = htons(port)
      C.inet_pton(AF_INET, target, addr.sin_addr)
      C.connect(fd, ffi.cast("struct sockaddr*", addr), ffi.sizeof(addr))
    end
    pcall(ffi.cdef, "int fcntl(int, int, ...);")
    local F_SETFL, O_NONBLOCK = 4, 2048
    local flags = C.fcntl(fd, 3, 0)
    C.fcntl(fd, F_SETFL, ffi.cast("int", flags + O_NONBLOCK))
    local buf = ffi.new("uint8_t[?]", 2048)
    return {
      send = function(self, raw)
        return C.send(fd, raw, #raw, 0) >= 0
      end,
      poll_response = function(self)
        local n = C.recv(fd, buf, 2048, 0)
        if n <= 0 then
          return nil
        end
        return ffi.string(buf, n)
      end,
      close = function(self)
        return C.close(fd)
      end
    }
  end
end
local run
run = function(opts)
  if opts == nil then
    opts = { }
  end
  local domains = opts.domains or {
    "www.example.com"
  }
  local max_queries = opts.max_queries or 1000
  local duration = opts.duration or 0
  local rate = opts.rate
  local now = opts.now or _now
  local timeout_ms = opts.timeout_ms or 1000
  local factory = opts.client_factory or _real_client_factory(opts.target, opts.port or 53, timeout_ms)
  local client = factory()
  local send_ts = { }
  local latencies = { }
  local sent = 0
  local received = 0
  local txid = 0
  local drain
  drain = function()
    local raw = client:poll_response()
    while raw do
      if #raw >= 2 then
        local rid = raw:byte(1) * 256 + raw:byte(2)
        do
          local ts = send_ts[rid]
          if ts then
            latencies[#latencies + 1] = (now() - ts) * 1000
            send_ts[rid] = nil
            received = received + 1
          end
        end
      end
      raw = client:poll_response()
    end
  end
  local t_start = now()
  local next_send = t_start
  while sent < max_queries do
    if duration > 0 and (now() - t_start) >= duration then
      break
    end
    if rate then
      while now() < next_send do
        drain()
      end
      next_send = next_send + (1 / rate)
    end
    txid = (txid % 65535) + 1
    local qname = domains[(sent % #domains) + 1]
    if client:send(encode_query(txid, qname)) then
      send_ts[txid] = now()
      sent = sent + 1
    end
    drain()
  end
  local deadline = now() + timeout_ms / 1000
  while received < sent and now() < deadline do
    drain()
  end
  client:close()
  local t_total = math.max(now() - t_start, 1e-9)
  local pct = report.percentiles(latencies)
  local dropped = sent - received
  return {
    sent = sent,
    received = received,
    dropped = dropped,
    timeouts = dropped,
    qps = sent / t_total,
    duration_s = t_total,
    p50 = pct.p50,
    p95 = pct.p95,
    p99 = pct.p99,
    min = pct.min,
    max = pct.max
  }
end
return {
  encode_query = encode_query,
  run = run,
  _real_client_factory = _real_client_factory
}
