local ffi, libnfq
do
  local _obj_0 = require("ffi_defs")
  ffi, libnfq = _obj_0.ffi, _obj_0.libnfq
end
local mac2s
mac2s = require("packet_utils").mac2s
local get_l2
get_l2 = function(nfad)
  local mac_src = "unknown"
  local mac_dst = "unknown"
  local mac_raw = "\0\0\0\0\0\0"
  local hw = libnfq.nfq_get_packet_hw(nfad)
  if hw ~= nil and hw.hw_addrlen > 0 then
    mac_raw = ffi.string(hw.hw_addr, 6)
    mac_src = mac2s(mac_raw)
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
