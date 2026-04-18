local ffi, ndpi_lib
do
  local _obj_0 = require("ffi_ndpi")
  ffi, ndpi_lib = _obj_0.ffi, _obj_0.ndpi_lib
end
local ndpi_ctx = nil
local flow_size = 0
local flow_buf = nil
local init_ndpi
init_ndpi = function()
  if not (ndpi_ctx) then
    ndpi_ctx = ndpi_lib.ndpi_init_detection_module(nil)
    assert(ndpi_ctx ~= nil, "ndpi_init_detection_module failed")
    local ret = ndpi_lib.ndpi_finalize_initialization(ndpi_ctx)
    assert(ret == 0, "ndpi_finalize_initialization failed (" .. tostring(ret) .. ")")
    flow_size = tonumber(ndpi_lib.ndpi_detection_get_sizeof_ndpi_flow_struct())
    flow_buf = ffi.new("uint8_t[?]", flow_size)
  end
end
local detect
detect = function(p, len)
  init_ndpi()
  ffi.fill(flow_buf, flow_size, 0)
  local flow = ffi.cast("ndpi_flow_struct*", flow_buf)
  ndpi_lib.ndpi_detection_process_packet(ndpi_ctx, flow, p, len, 0ULL, nil)
  local master = tonumber(ndpi_lib.ndpi_get_flow_masterprotocol(ndpi_ctx, flow))
  local app = tonumber(ndpi_lib.ndpi_get_flow_appprotocol(ndpi_ctx, flow))
  return master, app
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
