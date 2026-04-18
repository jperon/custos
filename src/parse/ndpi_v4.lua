local ffi, ndpi_lib, minor
do
  local _obj_0 = require("ffi_ndpi")
  ffi, ndpi_lib, minor = _obj_0.ffi, _obj_0.ndpi_lib, _obj_0.minor
end
local ndpi_ctx = nil
local flow_size = 0
local flow_buf = nil
local has_input_info = minor >= 6
local init_ndpi
init_ndpi = function()
  if not (ndpi_ctx) then
    ndpi_ctx = ndpi_lib.ndpi_init_detection_module(0)
    assert(ndpi_ctx ~= nil, "ndpi_init_detection_module failed")
    local bitmask = ffi.new("NDPI_PROTOCOL_BITMASK")
    ffi.fill(bitmask, ffi.sizeof(bitmask), 0xFF)
    ndpi_lib.ndpi_set_protocol_detection_bitmask2(ndpi_ctx, bitmask)
    ndpi_lib.ndpi_finalize_initialization(ndpi_ctx)
    flow_size = tonumber(ndpi_lib.ndpi_detection_get_sizeof_ndpi_flow_struct())
    flow_buf = ffi.new("uint8_t[?]", flow_size)
  end
end
local detect
detect = function(p, len)
  init_ndpi()
  ffi.fill(flow_buf, flow_size, 0)
  local flow = ffi.cast("ndpi_flow_struct*", flow_buf)
  local proto
  if has_input_info then
    proto = ndpi_lib.ndpi_detection_process_packet(ndpi_ctx, flow, p, len, 0ULL, nil)
  else
    proto = ndpi_lib.ndpi_detection_process_packet(ndpi_ctx, flow, p, len, 0ULL)
  end
  return tonumber(proto.master_protocol), tonumber(proto.app_protocol)
end
local cleanup
cleanup = function()
  if ndpi_ctx then
    ndpi_lib.ndpi_exit_detection_module(ndpi_ctx)
    ndpi_ctx = nil
    flow_buf = nil
  end
end
return {
  detect = detect,
  cleanup = cleanup
}
