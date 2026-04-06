local ffi = require("ffi")
local declare
declare = function(minor)
  ffi.cdef([[    /* ── nDPI 4.x opaque types ────────────────────────────────── */
    typedef struct ndpi_detection_module_struct ndpi_detection_module_struct;
    typedef struct ndpi_flow_struct             ndpi_flow_struct;

    /* ── Protocol bitmask: 512 bits = 16 × uint32_t (64 bytes) ── */
    typedef struct { uint32_t fds_bits[16]; } NDPI_PROTOCOL_BITMASK;

    /* ── ndpi_protocol (detection result, 4.x layout) ─────────── */
    typedef struct {
      uint16_t master_protocol;
      uint16_t app_protocol;
      int      category;
    } ndpi_protocol;

    /* ── Lifecycle ────────────────────────────────────────────── */
    ndpi_detection_module_struct *ndpi_init_detection_module(uint32_t prefs);
    void ndpi_finalize_initialization(ndpi_detection_module_struct *ndpi_str);
    void ndpi_exit_detection_module(ndpi_detection_module_struct *ndpi_struct);

    /* ── Protocol bitmask configuration ──────────────────────── */
    void ndpi_set_protocol_detection_bitmask2(
      ndpi_detection_module_struct *ndpi_struct,
      const NDPI_PROTOCOL_BITMASK *dbm);

    /* ── Flow struct size (for opaque allocation) ────────────── */
    uint32_t ndpi_detection_get_sizeof_ndpi_flow_struct(void);


  ]])
  if minor >= 6 then
    return ffi.cdef([[      typedef struct ndpi_flow_input_info ndpi_flow_input_info;
      ndpi_protocol ndpi_detection_process_packet(
        ndpi_detection_module_struct    *ndpi_struct,
        ndpi_flow_struct               *flow,
        const unsigned char            *packet,
        unsigned short                  packetlen,
        uint64_t                        packet_time_ms,
        const ndpi_flow_input_info     *input_info);
    ]])
  else
    return ffi.cdef([[      ndpi_protocol ndpi_detection_process_packet(
        ndpi_detection_module_struct *ndpi_struct,
        ndpi_flow_struct             *flow,
        const unsigned char          *packet,
        unsigned short                packetlen,
        uint64_t                      packet_time_ms);
    ]])
  end
end
return {
  declare = declare
}
