--- nDPI 4.2–4.8 detection backend.
-- Handles context initialisation (with NDPI_PROTOCOL_BITMASK),
-- per-packet protocol detection, and cleanup.
-- Used by the parse.ndpi facade; not intended for direct use.
-- @module parse.ndpi_v4

{ :ffi, :ndpi_lib, :minor } = require "ffi_ndpi"

ndpi_ctx  = nil
flow_size = 0
flow_buf  = nil

has_input_info = minor >= 6

--- Initialise the nDPI 4.x detection module (once).
-- @treturn cdata ndpi_detection_module_struct*.
init_ndpi = ->
  unless ndpi_ctx
    ndpi_ctx = ndpi_lib.ndpi_init_detection_module 0
    assert ndpi_ctx != nil, "ndpi_init_detection_module failed"
    bitmask = ffi.new "NDPI_PROTOCOL_BITMASK"
    ffi.fill bitmask, ffi.sizeof(bitmask), 0xFF
    ndpi_lib.ndpi_set_protocol_detection_bitmask2 ndpi_ctx, bitmask
    ndpi_lib.ndpi_finalize_initialization ndpi_ctx
    flow_size = tonumber ndpi_lib.ndpi_detection_get_sizeof_ndpi_flow_struct!
    flow_buf  = ffi.new "uint8_t[?]", flow_size

--- Run nDPI detection on a raw IP packet.
-- @tparam cdata p const uint8_t* pointer to the packet.
-- @tparam number len Packet length.
-- @treturn number master_protocol ID.
-- @treturn number app_protocol ID.
detect = (p, len) ->
  init_ndpi!
  ffi.fill flow_buf, flow_size, 0
  flow = ffi.cast "ndpi_flow_struct*", flow_buf
  proto = if has_input_info
    ndpi_lib.ndpi_detection_process_packet ndpi_ctx, flow, p, len, 0ULL, nil
  else
    ndpi_lib.ndpi_detection_process_packet ndpi_ctx, flow, p, len, 0ULL
  tonumber(proto.master_protocol), tonumber(proto.app_protocol)

--- Release the nDPI 4.x detection module.
cleanup = ->
  if ndpi_ctx
    ndpi_lib.ndpi_exit_detection_module ndpi_ctx
    ndpi_ctx  = nil
    flow_buf  = nil

{ :detect, :cleanup }
