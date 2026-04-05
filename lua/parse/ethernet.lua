local ffi, libnfq
do
  local _obj_0 = require("ffi_defs")
  ffi, libnfq = _obj_0.ffi, _obj_0.libnfq
end
local format_mac
format_mac = function(hw_ptr)
  return string.format("%02x:%02x:%02x:%02x:%02x:%02x", hw_ptr.hw_addr[0], hw_ptr.hw_addr[1], hw_ptr.hw_addr[2], hw_ptr.hw_addr[3], hw_ptr.hw_addr[4], hw_ptr.hw_addr[5])
end
local get_l2
get_l2 = function(nfad)
  local hw = libnfq.nfq_get_packet_hw(nfad)
  local mac_src
  if hw ~= nil and hw.hw_addrlen > 0 then
    mac_src = format_mac(hw)
  else
    mac_src = "unknown"
  end
  local in_ifindex = tonumber(libnfq.nfq_get_indev(nfad))
  return {
    mac_src = mac_src,
    in_ifindex = in_ifindex
  }
end
return {
  get_l2 = get_l2,
  format_mac = format_mac
}
