local ffi = require("ffi")
pcall(function()
  return ffi.cdef([[    int inet_pton(int af, const char *src, void *dst);
  ]])
end)
local AF_INET = 2
local AF_INET6 = 10
local parse_ip
parse_ip = function(s)
  local buf = ffi.new("uint8_t[16]")
  if s:find(":", 1, true) then
    if ffi.C.inet_pton(AF_INET6, s, buf) == 1 then
      return buf
    end
  else
    local tmp = ffi.new("uint8_t[4]")
    if ffi.C.inet_pton(AF_INET, s, tmp) == 1 then
      ffi.fill(buf, 10, 0)
      buf[10] = 0xFF
      buf[11] = 0xFF
      buf[12] = tmp[0]
      buf[13] = tmp[1]
      buf[14] = tmp[2]
      buf[15] = tmp[3]
      return buf
    end
  end
  return nil
end
local parse_net
parse_net = function(s)
  local addr_s, mask_s = s:match("^([^/]+)/?(%d*)$")
  if not (addr_s) then
    return nil
  end
  local is_v6 = (addr_s:find(":", 1, true) and true) or false
  local mask_bits = tonumber(mask_s) or (is_v6 and 128 or 32)
  local off = is_v6 and 0 or 12
  local addr = parse_ip(addr_s)
  if not (addr) then
    return nil
  end
  return {
    addr = addr,
    mask_bits = mask_bits,
    is_v6 = is_v6,
    off = off
  }
end
local bit = require("bit")
local ip_in_net
ip_in_net = function(ip_buf, net)
  local off = net.off
  local mask_bits = net.mask_bits
  local full_bytes = math.floor(mask_bits / 8)
  local rem_bits = mask_bits % 8
  for i = 0, full_bytes - 1 do
    if ip_buf[off + i] ~= net.addr[off + i] then
      return false
    end
  end
  if rem_bits > 0 then
    local mask = bit.band(0xFF, bit.bnot(bit.rshift(0xFF, rem_bits)))
    if bit.band(ip_buf[off + full_bytes], mask) ~= bit.band(net.addr[off + full_bytes], mask) then
      return false
    end
  end
  return true
end
local Net
Net = function(s)
  local net = parse_net(s)
  if not (net) then
    return nil
  end
  return {
    contains = function(self, ip_s)
      local ip = parse_ip(ip_s)
      if not (ip) then
        return false
      end
      return ip_in_net(ip, net)
    end
  }
end
return {
  Net = Net,
  parse_ip = parse_ip,
  parse_net = parse_net,
  ip_in_net = ip_in_net
}
