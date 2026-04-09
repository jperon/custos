local ffi = require("ffi")
local xxhash = require("ffi_xxhash")
ffi.cdef([[  void qsort(void* base, size_t n, size_t size, int (*cmp)(const void*, const void*));
]])
if #arg < 2 then
  io.stderr:write("Usage: luajit lua/filter/convert.lua <input.domains> <output.bin>\n")
  os.exit(1)
end
local input_path = arg[1]
local output_path = arg[2]
local fh = io.open(input_path, "r")
if not fh then
  io.stderr:write("Impossible d'ouvrir : " .. tostring(input_path) .. "\n")
  os.exit(1)
end
local hashes = { }
local seen = { }
local n = 0
for line in fh:lines() do
  local _continue_0 = false
  repeat
    local domain = line:match("^%s*(.-)%s*$")
    domain = domain:match("^([^#]*)" or "")
    domain = domain:match("^%s*(.-)%s*$")
    if domain == "" then
      _continue_0 = true
      break
    end
    if seen[domain] then
      _continue_0 = true
      break
    end
    seen[domain] = true
    local h = xxhash.xxh64(domain)
    n = n + 1
    hashes[n] = h
    _continue_0 = true
  until true
  if not _continue_0 then
    break
  end
end
fh:close()
if n == 0 then
  io.stderr:write("Aucun domaine valide dans " .. tostring(input_path) .. "\n")
  os.exit(1)
end
table.sort(hashes, function(a, b)
  return a < b
end)
local arr = ffi.new("uint64_t[?]", n)
for i = 1, n do
  arr[i - 1] = hashes[i]
end
local out = io.open(output_path, "wb")
if not out then
  io.stderr:write("Impossible d'écrire : " .. tostring(output_path) .. "\n")
  os.exit(1)
end
out:write(ffi.string(arr, n * 8))
out:close()
return io.stderr:write(tostring(n) .. " domaines → " .. tostring(output_path) .. " (" .. tostring(n * 8) .. " octets)\n")
