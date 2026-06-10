local new_stream
new_stream = require("ipparse.l4.tcp_stream").new
local IPV6_EXT_HDRS = {
  [0] = true,
  [43] = true,
  [44] = true,
  [51] = false,
  [60] = true,
  [135] = true,
  [139] = true,
  [140] = true
}
local skip_ipv6_ext_hdrs
skip_ipv6_ext_hdrs = function(p, len, first_nh)
  local nh = first_nh
  local off = 40
  while IPV6_EXT_HDRS[nh] ~= nil do
    if off + 2 > len then
      return nil, nil
    end
    local next_nh = p[off]
    local ext_size
    if nh == 51 then
      ext_size = (p[off + 1] + 2) * 4
    else
      ext_size = (p[off + 1] + 1) * 8
    end
    if ext_size < 8 or off + ext_size > len then
      return nil, nil
    end
    off = off + ext_size
    nh = next_nh
  end
  return nh, off
end
local dns_tcp_complete
dns_tcp_complete = function(buf)
  if #buf < 2 then
    return false
  end
  return #buf >= 2 + buf:byte(1) * 256 + buf:byte(2)
end
local new_dns_tcp_stream
new_dns_tcp_stream = function(check_complete)
  if check_complete == nil then
    check_complete = dns_tcp_complete
  end
  return new_stream(check_complete)
end
return {
  skip_ipv6_ext_hdrs = skip_ipv6_ext_hdrs,
  dns_tcp_complete = dns_tcp_complete,
  new_dns_tcp_stream = new_dns_tcp_stream
}
