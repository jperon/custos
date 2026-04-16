local ffi, libnfq
do
  local _obj_0 = require("ffi_defs")
  ffi, libnfq = _obj_0.ffi, _obj_0.libnfq
end
local BRIDGE_MODE, NFQ_BRIDGE_MODE
do
  local _obj_0 = require("config")
  BRIDGE_MODE, NFQ_BRIDGE_MODE = _obj_0.BRIDGE_MODE, _obj_0.NFQ_BRIDGE_MODE
end
local bit = require("bit")
local ETH_OFFSET = NFQ_BRIDGE_MODE and 14 or 0
local format_mac_ptr
format_mac_ptr = function(p, o)
  return string.format("%02x:%02x:%02x:%02x:%02x:%02x", p[o], p[o + 1], p[o + 2], p[o + 3], p[o + 4], p[o + 5])
end
local format_mac
format_mac = function(hw_ptr)
  return string.format("%02x:%02x:%02x:%02x:%02x:%02x", hw_ptr.hw_addr[0], hw_ptr.hw_addr[1], hw_ptr.hw_addr[2], hw_ptr.hw_addr[3], hw_ptr.hw_addr[4], hw_ptr.hw_addr[5])
end
local get_l2
get_l2 = function(nfad, raw)
  local mac_src = "unknown"
  local mac_raw = "\0\0\0\0\0\0"
  if NFQ_BRIDGE_MODE and raw and #raw >= 12 then
    local p = ffi.cast("const uint8_t*", raw)
    mac_src = format_mac_ptr(p, 6)
    mac_raw = ffi.string(p + 6, 6)
  else
    local hw = libnfq.nfq_get_packet_hw(nfad)
    if hw ~= nil and hw.hw_addrlen > 0 then
      mac_src = format_mac(hw)
      mac_raw = ffi.string(hw.hw_addr, 6)
    end
  end
  local in_ifindex = tonumber(libnfq.nfq_get_indev(nfad))
  local mark = tonumber(libnfq.nfq_get_nfmark(nfad))
  local vlan = mark > 0 and mark or nil
  return {
    mac_src = mac_src,
    mac_raw = mac_raw,
    in_ifindex = in_ifindex,
    vlan = vlan
  }
end
return {
  get_l2 = get_l2,
  format_mac = format_mac,
  format_mac_ptr = format_mac_ptr,
  ETH_OFFSET = ETH_OFFSET
}
