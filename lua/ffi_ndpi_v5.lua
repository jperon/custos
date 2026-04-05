local ffi = require("ffi")
local declare
declare = function()
  return ffi.cdef([[    /* ── nDPI 5.x opaque types ────────────────────────────────── */
    typedef struct ndpi_detection_module_struct ndpi_detection_module_struct;
    typedef struct ndpi_flow_struct             ndpi_flow_struct;
    typedef struct ndpi_global_context          ndpi_global_context;
    typedef struct ndpi_flow_input_info         ndpi_flow_input_info;

    /* ── ndpi_protocol: opaque return type ────────────────────── */
    /* The v5 ndpi_protocol struct contains proto_stack, fpc, breed,
       state, etc. — its exact layout depends on compile-time defines.
       We declare an oversized opaque blob so the ABI hidden-pointer
       return works correctly on x86_64, then read protocol IDs via
       accessor functions instead of the struct fields. */
    typedef struct { uint8_t _opaque[128]; } ndpi_protocol;

    /* ── Lifecycle (changed signatures in 5.x) ───────────────── */
    ndpi_detection_module_struct *ndpi_init_detection_module(
      ndpi_global_context *g_ctx);
    int  ndpi_finalize_initialization(ndpi_detection_module_struct *ndpi_str);
    void ndpi_exit_detection_module(ndpi_detection_module_struct *ndpi_struct);

    /* ── Flow struct size (for opaque allocation) ────────────── */
    uint32_t ndpi_detection_get_sizeof_ndpi_flow_struct(void);

    /* ── Main detection (6-arg, input_info optional) ─────────── */
    ndpi_protocol ndpi_detection_process_packet(
      ndpi_detection_module_struct *ndpi_struct,
      ndpi_flow_struct             *flow,
      const unsigned char          *packet,
      unsigned short                packetlen,
      uint64_t                      packet_time_ms,
      ndpi_flow_input_info         *input_info);

    /* ── Protocol accessors (read from flow, not return value) ── */
    uint16_t ndpi_get_flow_masterprotocol(
      ndpi_detection_module_struct *ndpi_struct,
      ndpi_flow_struct             *flow);
    uint16_t ndpi_get_flow_appprotocol(
      ndpi_detection_module_struct *ndpi_struct,
      ndpi_flow_struct             *flow);

    /* ── Protocol name getter ────────────────────────────────── */
    char *ndpi_get_proto_name(
      ndpi_detection_module_struct *ndpi_mod,
      uint16_t proto_id);
  ]])
end
return {
  declare = declare
}
