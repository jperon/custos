local IP4 = require("ipparse.l3.ip4")
local data_new
data_new = require("data").new
local sort
sort = table.sort
local lshift
lshift = require("ipparse.lib.bit_compat").lshift
local MAX_PENDING = 64
local fragmented = { }
local pending = 0
local order, order_first, order_last = { }, 1, 0
local evict_oldest
evict_oldest = function()
  while order_first <= order_last do
    local key = order[order_first]
    order[order_first] = nil
    order_first = order_first + 1
    if fragmented[key] then
      fragmented[key] = nil
      pending = pending - 1
      return 
    end
  end
end
return {
  collect = function(self, _skb)
    local id, off, data_off, data_len, mf
    id, off, data_off, data_len, mf = self.id, self.off, self.data_off, self.data_len, self.mf
    local key = tostring(self.src) .. tostring(self.dst) .. tostring(self.protocol) .. tostring(id)
    local fragments = fragmented[key]
    if not (fragments) then
      if pending >= MAX_PENDING then
        evict_oldest()
      end
      fragments = { }
      fragmented[key] = fragments
      pending = pending + 1
      order_last = order_last + 1
      order[order_last] = key
    end
    local frag_off = lshift(self.fragmentation_off, 3)
    local total_len = off + frag_off + data_off + data_len
    local max_len = total_len > 10240 and 65535 or 10240
    if max_len > 65535 then
      return false, "Invalid size"
    end
    local skb = fragments.skb
    if skb then
      if #skb < max_len then
        local tmp = data_new(max_len)
        tmp:setstring(0, skb:getstring(0))
        skb = tmp
      end
    else
      skb = data_new(max_len)
    end
    fragments.skb = skb
    if frag_off == 0 then
      skb:setstring(0, _skb:getstring(0, (off + data_off + data_len - 1)))
    else
      local offset = off + data_off
      local max_offset = offset + data_len - 1
      if max_offset > #_skb then
        return false, "Invalid data offset"
      end
      skb:setstring((frag_off + offset), _skb:getstring(offset, max_offset))
    end
    fragments[#fragments + 1] = {
      frag_off = frag_off,
      off = off,
      data_off = data_off,
      data_len = data_len,
      mf = mf
    }
    sort(fragments, function(a, b)
      return a.frag_off < b.frag_off
    end)
    local lastfrag = fragments[#fragments]
    if lastfrag.mf ~= 0 then
      return 
    end
    off, frag_off, data_off, data_len = lastfrag.off, lastfrag.frag_off, lastfrag.data_off, lastfrag.data_len
    total_len = off + frag_off + data_off + data_len
    fragmented[key] = nil
    pending = pending - 1
    local ip = IP4.parse(skb)
    return ip, self
  end
}
