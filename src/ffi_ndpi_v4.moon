--- FFI cdef declarations for nDPI 4.2–4.8.
-- Applies version-specific ffi.cdef for the nDPI 4.x API.
-- Called by the ffi_ndpi facade; not intended for direct use.
-- @module ffi_ndpi_v4

ffi = require "ffi"

--- Apply cdef declarations for nDPI 4.x.
-- @tparam number minor Minor version number (2, 4, 6, 8).
declare = (minor) ->
  ffi.cdef [[
    /* ── nDPI 4.x opaque types ────────────────────────────────── */
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

    /* ── Protocol name getter ────────────────────────────────── */
    char *ndpi_get_proto_name(
      ndpi_detection_module_struct *ndpi_mod,
      uint16_t proto_id);
  ]]

  -- nDPI 4.6+ added a 6th parameter (ndpi_flow_input_info*) to
  -- ndpi_detection_process_packet. Earlier versions use 5 args.
  if minor >= 6
    ffi.cdef [[
      typedef struct ndpi_flow_input_info ndpi_flow_input_info;
      ndpi_protocol ndpi_detection_process_packet(
        ndpi_detection_module_struct    *ndpi_struct,
        ndpi_flow_struct               *flow,
        const unsigned char            *packet,
        unsigned short                  packetlen,
        uint64_t                        packet_time_ms,
        const ndpi_flow_input_info     *input_info);
    ]]
  else
    ffi.cdef [[
      ndpi_protocol ndpi_detection_process_packet(
        ndpi_detection_module_struct *ndpi_struct,
        ndpi_flow_struct             *flow,
        const unsigned char          *packet,
        unsigned short                packetlen,
        uint64_t                      packet_time_ms);
    ]]

{ :declare }
