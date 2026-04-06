--- Version-detecting facade for libndpi FFI declarations.
-- Loads libndpi.so, detects the version via ndpi_revision(),
-- then dispatches to ffi_ndpi_v4 (4.2–4.8) or ffi_ndpi_v5 (5.0+)
-- for the appropriate cdef declarations.
-- @module ffi_ndpi

ffi = require "ffi"

-- Minimal cdef to detect the library version.
-- Note: inet_ntop est déclaré dans ffi_defs.moon (ffi.C global), pas ici.
ffi.cdef [[
  const char *ndpi_revision(void);
]]

--- Tente de charger libndpi parmi plusieurs noms candidats.
-- Gère les noms non-versionnés (dev packages, Arch) et les
-- sonames versionnés Debian (à partir du paquet runtime).
ndpi_names = { "ndpi", "libndpi.so.5", "libndpi.so.4.2", "libndpi.so.4" }
ndpi_lib = nil
for name in *ndpi_names
  ok, lib = pcall ffi.load, name
  if ok
    ndpi_lib = lib
    break
unless ndpi_lib
  error "libndpi not found (tried: #{table.concat ndpi_names, ', '})"

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
