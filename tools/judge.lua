local ffi = require("ffi")
do
  local script_dir = arg[0]:match("^(.*)/[^/]+$") or "."
  local project_root = script_dir:match("^(.*)/tools$") or script_dir .. "/.."
  local lua_dir = project_root .. "/lua"
  package.path = lua_dir .. "/?.lua;" .. lua_dir .. "/?/init.lua;" .. package.path
end
local usage
usage = function()
  io.stderr:write("Usage: moon tools/judge.moon <bin-dir> [<bin-dir> ...] <domain>\n")
  return os.exit(2)
end
local domain = arg[#arg]
local bin_dirs
do
  local _accum_0 = { }
  local _len_0 = 1
  for i = 1, #arg - 1 do
    _accum_0[_len_0] = arg[i]
    _len_0 = _len_0 + 1
  end
  bin_dirs = _accum_0
end
if not (#bin_dirs > 0 and domain and domain ~= "") then
  usage()
end
local bin48 = require("filter.lib.bin48")
local xxhash = require("ffi_xxhash")
pcall(function()
  return ffi.cdef([[  int open(const char *path, int oflag, ...);
  int close(int fd);
  long lseek(int fd, long offset, int whence);
  void *mmap(void *addr, size_t len, int prot, int flags, int fd, long offset);
  int munmap(void *addr, size_t len);
]])
end)
local O_RDONLY = 0
local SEEK_END = 2
local PROT_READ = 0x1
local MAP_SHARED = 0x01
local MAP_FAILED = ffi.cast("void*", -1)
local load_bin
load_bin = function(path)
  local fd = ffi.C.open(path, O_RDONLY, 0)
  if fd < 0 then
    return nil, "cannot open '" .. tostring(path) .. "'"
  end
  local size = tonumber(ffi.C.lseek(fd, 0, SEEK_END))
  local rec_size = 0
  if size > 0 and size % 6 == 0 then
    rec_size = 6
  end
  if size > 0 and size % 6 ~= 0 and size % 8 == 0 then
    rec_size = 8
  end
  if size == 0 then
    ffi.C.close(fd)
    return nil, nil
  end
  if rec_size == 0 then
    ffi.C.close(fd)
    return nil, "taille " .. tostring(size) .. " non multiple de 6 ou 8 pour '" .. tostring(path) .. "'"
  end
  local n = size / rec_size
  local ptr = ffi.C.mmap(nil, size, PROT_READ, MAP_SHARED, fd, 0)
  ffi.C.close(fd)
  if ptr == MAP_FAILED then
    return nil, "mmap failed for '" .. tostring(path) .. "'"
  end
  local arr = ffi.cast("const uint8_t*", ptr)
  return arr, n, rec_size
end
local bsearch_u64
bsearch_u64 = function(arr8, n, target)
  local TWO32 = 0x100000000ULL
  local _u32 = ffi.typeof("const uint32_t*")
  local lo, hi = 0, n - 1
  while lo <= hi do
    local mid = math.floor((lo + hi) * 0.5)
    local b = arr8 + mid * 8
    local v = ffi.cast("uint64_t", (ffi.cast(_u32, b))[0]) + ffi.cast("uint64_t", (ffi.cast(_u32, b + 4))[0]) * TWO32
    if v == target then
      return true
    elseif v < target then
      lo = mid + 1
    else
      hi = mid - 1
    end
  end
  return false
end
local check
check = function(arr, n, rec_size, dom)
  local bsearch_fn = rec_size == 6 and (function(a, nn, h)
    return bin48.bsearch(a, nn, bin48.truncate(h))
  end) or (function(a, nn, h)
    return bsearch_u64(a, nn, h)
  end)
  local h = xxhash.xxh64(dom)
  if bsearch_fn(arr, n, h) then
    return "exact"
  end
  local pos = dom:find(".", 1, true)
  while pos do
    local suffix = dom:sub(pos + 1)
    h = xxhash.xxh64(suffix)
    if bsearch_fn(arr, n, h) then
      return "suffix:" .. tostring(suffix)
    end
    pos = dom:find(".", pos + 1, true)
  end
  return nil
end
local bin_entries = { }
local multi_dir = #bin_dirs > 1
for _index_0 = 1, #bin_dirs do
  local dir = bin_dirs[_index_0]
  local pipe = io.popen("ls -1 " .. dir .. "/*.bin 2>/dev/null")
  if pipe then
    for path in pipe:lines() do
      local name = path:match("([^/]+)%.bin$")
      local label = multi_dir and (dir:gsub("/*$", "")) .. "/" .. name or name
      bin_entries[#bin_entries + 1] = {
        path = path,
        label = label
      }
    end
    pipe:close()
  end
end
if #bin_entries == 0 then
  io.stderr:write("Aucun fichier .bin trouvé\n")
  os.exit(2)
end
local exact_lists = { }
local suffix_lists = { }
for _index_0 = 1, #bin_entries do
  local _continue_0 = false
  repeat
    local _des_0 = bin_entries[_index_0]
    local path, label
    path, label = _des_0.path, _des_0.label
    local arr, n, rec_size = load_bin(path)
    if not (arr) then
      if n then
        io.stderr:write("[warn] " .. tostring(n) .. "\n")
      end
      _continue_0 = true
      break
    end
    local result = check(arr, n, rec_size, domain)
    if result == "exact" then
      exact_lists[#exact_lists + 1] = label
    elseif result then
      local parent = result:sub(8)
      local _update_0 = parent
      suffix_lists[_update_0] = suffix_lists[_update_0] or { }
      local t = suffix_lists[parent]
      t[#t + 1] = label
    end
    _continue_0 = true
  until true
  if not _continue_0 then
    break
  end
end
local found_any = #exact_lists > 0 or next(suffix_lists) ~= nil
if not (found_any) then
  io.stderr:write(tostring(domain) .. " : aucun match dans " .. tostring(table.concat(bin_dirs, ", ")) .. "\n")
  os.exit(1)
end
if #exact_lists > 0 then
  table.sort(exact_lists)
  print("Exact (" .. tostring(domain) .. ") : " .. tostring(table.concat(exact_lists, ", ")))
end
local parents
do
  local _accum_0 = { }
  local _len_0 = 1
  for p in pairs(suffix_lists) do
    _accum_0[_len_0] = p
    _len_0 = _len_0 + 1
  end
  parents = _accum_0
end
table.sort(parents, function(a, b)
  return #a > #b
end)
for _index_0 = 1, #parents do
  local parent = parents[_index_0]
  local names = suffix_lists[parent]
  table.sort(names)
  print("Suffixe (" .. tostring(parent) .. ") : " .. tostring(table.concat(names, ", ")))
end
