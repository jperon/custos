--- Version-detecting facade for libndpi FFI declarations.
-- Loads libndpi.so, detects the version via ndpi_revision(),
-- then dispatches to ffi_ndpi_v4 (4.2–4.8) or ffi_ndpi_v5 (5.0+)
-- for the appropriate cdef declarations.
-- @module ffi_ndpi

ffi = require "ffi"

-- Minimal cdef to detect the library version.
ffi.cdef [[
  const char *ndpi_revision(void);
  const char *inet_ntop(int af, const void *src,
                        char *dst, unsigned int size);
]]

--- Load libndpi from the system library path.
ok, ndpi_lib = pcall ffi.load, "ndpi"
unless ok
  error "libndpi not found. Install libndpi-dev (4.2+) or libndpi (5.0+)"

--- Parse version string from ndpi_revision().
rev   = ffi.string ndpi_lib.ndpi_revision!
major, minor = rev\match "(%d+)%.(%d+)"
major = tonumber(major) or 0
minor = tonumber(minor) or 0

--- Dispatch to the correct cdef module.
if major >= 5
  require("ffi_ndpi_v5").declare!
else
  require("ffi_ndpi_v4").declare minor

{ :ffi, ndpi: ndpi_lib, :ndpi_lib, :major, :minor, :rev }
