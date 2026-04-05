--- nDPI 5.0+ detection backend.
-- Handles context initialisation (no bitmask, all protocols enabled),
-- per-packet protocol detection via accessors, and cleanup.
-- Used by the parse.ndpi facade; not intended for direct use.
-- @module parse.ndpi_v5

{ :ffi, :ndpi_lib } = require "ffi_ndpi"

ndpi_ctx  = nil
flow_size = 0
flow_buf  = nil

--- Initialise the nDPI 5.x detection module (once).
-- The context is stored as module-level state; subsequent calls are no-ops.
-- @treturn nil
init_ndpi = ->
  unless ndpi_ctx
    ndpi_ctx = ndpi_lib.ndpi_init_detection_module nil
    assert ndpi_ctx != nil, "ndpi_init_detection_module failed"
    -- nDPI 5.0: all protocols enabled by default, no bitmask2 call.
    ret = ndpi_lib.ndpi_finalize_initialization ndpi_ctx
    assert ret == 0, "ndpi_finalize_initialization failed (#{ret})"
    flow_size = tonumber ndpi_lib.ndpi_detection_get_sizeof_ndpi_flow_struct!
    flow_buf  = ffi.new "uint8_t[?]", flow_size

--- Run nDPI detection on a raw IP packet.
-- Uses accessor functions to read protocol IDs from the flow struct,
-- avoiding dependence on the opaque ndpi_protocol return layout.
-- @tparam cdata p const uint8_t* pointer to the packet.
-- @tparam number len Packet length.
-- @treturn number master_protocol ID.
-- @treturn number app_protocol ID.
detect = (p, len) ->
  init_ndpi!
  ffi.fill flow_buf, flow_size, 0
  flow = ffi.cast "ndpi_flow_struct*", flow_buf
  ndpi_lib.ndpi_detection_process_packet ndpi_ctx, flow, p, len, 0ULL, nil
  master = tonumber ndpi_lib.ndpi_get_flow_masterprotocol ndpi_ctx, flow
  app    = tonumber ndpi_lib.ndpi_get_flow_appprotocol ndpi_ctx, flow
  master, app

--- Release the nDPI 5.x detection module.
cleanup = ->
  if ndpi_ctx
    ndpi_lib.ndpi_exit_detection_module ndpi_ctx
    ndpi_ctx  = nil
    flow_buf  = nil

{ :detect, :cleanup }
