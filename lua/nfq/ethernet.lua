local ffi, libnfq
do
  local _obj_0 = require("ffi_defs")
  ffi, libnfq = _obj_0.ffi, _obj_0.libnfq
end
local get_l2
get_l2 = function(nfad)
  local mac_src = "unknown"
  local mac_dst = "unknown"
  local mac_raw = "\0\0\0\0\0\0"
  local hw = libnfq.nfq_get_packet_hw(nfad)
  if hw ~= nil and hw.hw_addrlen > 0 then
    mac_src = string.format("%02x:%02x:%02x:%02x:%02x:%02x", hw.hw_addr[0], hw.hw_addr[1], hw.hw_addr[2], hw.hw_addr[3], hw.hw_addr[4], hw.hw_addr[5])
    mac_raw = ffi.string(hw.hw_addr, 6)
  end
  local in_ifindex = tonumber(libnfq.nfq_get_indev(nfad))
  local mark = tonumber(libnfq.nfq_get_nfmark(nfad))
  local vlan = mark > 0 and mark or nil
  return {
    mac_src = mac_src,
    mac_dst = mac_dst,
    mac_raw = mac_raw,
    in_ifindex = in_ifindex,
    vlan = vlan
  }
end
return {
  get_l2 = get_l2
}
