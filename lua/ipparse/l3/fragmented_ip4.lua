local sort
sort = table.sort
require("ipparse")
local sp
sp = require("ipparse.lib.pack_compat").pack
local band, lshift
do
  local _obj_0 = require("ipparse.lib.bit_compat")
  band, lshift = _obj_0.band, _obj_0.lshift
end
local MAX_PENDING = 64
local MAX_FRAGMENTS = 256
local fragmented = { }
local pending = 0
local seq = 0
local order, order_first, order_last = { }, 1, 0
local evict_oldest
evict_oldest = function()
  while order_first <= order_last do
    local current = order_first
    local key = order[current]
    order[current] = nil
    order_first = order_first + 1
    if key ~= nil and fragmented[key] and fragmented[key].seq == current then
      fragmented[key] = nil
      pending = pending - 1
      return 
    end
  end
end
local drop_flow
drop_flow = function(key)
  if fragmented[key] then
    order[fragmented[key].seq] = nil
    fragmented[key] = nil
    pending = pending - 1
  end
end
local reassemble
reassemble = function(chunks, total)
  local offsets
  do
    local _accum_0 = { }
    local _len_0 = 1
    for off, _ in pairs(chunks) do
      _accum_0[_len_0] = off
      _len_0 = _len_0 + 1
    end
    offsets = _accum_0
  end
  sort(offsets)
  local out = { }
  local expected = 0
  for _index_0 = 1, #offsets do
    local _continue_0 = false
    repeat
      local off = offsets[_index_0]
      local chunk = chunks[off]
      local chunk_end = off + #chunk - 1
      if chunk_end < expected then
        _continue_0 = true
        break
      end
      if off > expected then
        break
      end
      local start_idx = expected > off and (expected - off + 1) or 1
      out[#out + 1] = chunk:sub(start_idx)
      expected = chunk_end + 1
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  if expected < total then
    return nil
  end
  return table.concat(out)
end
local collect
collect = function(ip, pkt)
  local header_len = ip.data_off - ip.off
  if ip.total_len < header_len then
    return nil, "truncated packet"
  end
  local last = ip.off + ip.total_len - 1
  if last > #pkt then
    return nil, "truncated packet"
  end
  local payload = pkt:sub(ip.data_off, last)
  local frag_off = lshift(band(ip.ff, 0x1fff), 3)
  local mf = band(ip.ff, 0x2000) ~= 0
  if frag_off == 0 and not mf then
    return payload, ip
  end
  local key = sp(">c4 c4 B H", ip.src, ip.dst, ip.protocol, ip.id)
  if frag_off + #payload > 65535 then
    drop_flow(key)
    return nil, "fragment exceeds 65535 bytes"
  end
  if mf and (#payload % 8) ~= 0 then
    return nil, "invalid fragment length"
  end
  local state = fragmented[key]
  if not (state) then
    if pending >= MAX_PENDING then
      evict_oldest()
    end
    seq = seq + 1
    state = {
      chunks = { },
      total = nil,
      first = nil,
      n = 0,
      seq = seq
    }
    fragmented[key] = state
    pending = pending + 1
    order_last = seq
    order[seq] = key
  end
  if not state.chunks[frag_off] then
    if state.n >= MAX_FRAGMENTS then
      drop_flow(key)
      return nil, "too many fragments"
    end
    state.n = state.n + 1
  end
  state.chunks[frag_off] = payload
  if frag_off == 0 then
    state.first = ip
  end
  if not (mf) then
    state.total = frag_off + #payload
  end
  if state.total and state.first then
    local data = reassemble(state.chunks, state.total)
    if data then
      local first = state.first
      drop_flow(key)
      return data, first
    end
  end
  return nil
end
local reset
reset = function()
  fragmented = { }
  pending = 0
  seq = 0
  order, order_first, order_last = { }, 1, 0
end
local stats
stats = function()
  local queued = 0
  for _ in pairs(order) do
    queued = queued + 1
  end
  return pending, queued
end
return {
  collect = collect,
  reset = reset,
  stats = stats,
  MAX_PENDING = MAX_PENDING
}
