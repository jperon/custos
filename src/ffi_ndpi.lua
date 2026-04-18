local ffi = require("ffi")
ffi.cdef([[  const char *ndpi_revision(void);
]])
local ndpi_names = {
  "ndpi",
  "libndpi.so.5",
  "libndpi.so.4.2",
  "libndpi.so.4"
}
local ndpi_lib = nil
for _index_0 = 1, #ndpi_names do
  local name = ndpi_names[_index_0]
  local ok, lib = pcall(ffi.load, name)
  if ok then
    ndpi_lib = lib
    break
  end
end
if not (ndpi_lib) then
  error("libndpi not found (tried: " .. tostring(table.concat(ndpi_names, ', ')) .. ")")
end
local rev = ffi.string(ndpi_lib.ndpi_revision())
local major, minor = rev:match("(%d+)%.(%d+)")
major = tonumber(major) or 0
minor = tonumber(minor) or 0
if major >= 5 then
  require("ffi_ndpi_v5").declare()
else
  require("ffi_ndpi_v4").declare(minor)
end
return {
  ffi = ffi,
  ndpi = ndpi_lib,
  ndpi_lib = ndpi_lib,
  major = major,
  minor = minor,
  rev = rev
}
