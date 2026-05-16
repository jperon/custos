local ffi = require("ffi")
local load_list
load_list = function(path)
  local xxhash = require("ffi_xxhash")
  local bsearch_m = require("filter.lib.bsearch")
  local fh = io.open(path, "rb")
  if not (fh) then
    return nil, "Cannot open " .. tostring(path)
  end
  local data = fh:read("*a")
  fh:close()
  if path:match("%.bin$") then
    local n = math.floor(#data / 8)
    if n == 0 then
      return nil, "Empty bin file: " .. tostring(path)
    end
    local arr = ffi.new("uint64_t[?]", n)
    ffi.copy(arr, data, n * 8)
    return arr, n
  else
    local hashes = { }
    for line in data:gmatch("[^\n]+") do
      local domain = line:match("^%s*(.-)%s*$")
      domain = (domain:match("^([^#]*)")) or ""
      domain = domain:match("^%s*(.-)%s*$")
      if domain ~= "" then
        hashes[#hashes + 1] = xxhash.xxh64(domain)
      end
    end
    local n = #hashes
    if n == 0 then
      return nil, "Empty domains file: " .. tostring(path)
    end
    table.sort(hashes, function(a, b)
      return a < b
    end)
    local arr = ffi.new("uint64_t[?]", n)
    for i = 1, n do
      arr[i - 1] = hashes[i]
    end
    return arr, n
  end
end
local lookup
lookup = function(arr, n, domain)
  local xxh64
  xxh64 = require("ffi_xxhash").xxh64
  local bsearch
  bsearch = require("filter.lib.bsearch").bsearch
  if bsearch(arr, n, xxh64(domain)) then
    return true
  end
  local pos = domain:find(".", 1, true)
  while pos do
    local suffix = domain:sub(pos + 1)
    if bsearch(arr, n, xxh64(suffix)) then
      return true
    end
    pos = domain:find(".", pos + 1, true)
  end
  return false
end
return function(cfg)
  return function(listname)
    if not (cfg.domainlists_dir) then
      return {
        capabilities = {
          worker = true,
          nft = false,
          nft_dynamic = false
        },
        eval = function(req)
          return false, "domainlists_dir non défini"
        end
      }
    end
    if listname:match("^/" or listname:match("%.%." or listname:match("%.bin$"))) then
      return {
        capabilities = {
          worker = true,
          nft = false,
          nft_dynamic = false
        },
        eval = function(req)
          return false, "Nom de liste invalide: '" .. tostring(listname) .. "'"
        end
      }
    end
    local base = (cfg.domainlists_dir:gsub("/*$", "")) .. "/" .. listname
    local path = base .. ".bin"
    local arr, n_or_err = load_list(path)
    if not (arr) then
      arr, n_or_err = load_list(base .. ".domains")
    end
    if not (arr) then
      return {
        capabilities = {
          worker = true,
          nft = false,
          nft_dynamic = false
        },
        eval = function(req)
          return false, "Cannot load domain list '" .. tostring(listname) .. "': " .. tostring(n_or_err)
        end
      }
    end
    local n = n_or_err
    return {
      capabilities = {
        worker = true,
        nft = false,
        nft_dynamic = false
      },
      listname = listname,
      eval = function(req)
        local domain = req.domain
        if not (domain) then
          return false, "Missing domain in request"
        end
        if lookup(arr, n, domain) then
          return true, "Domain matched in list '" .. tostring(listname) .. "'"
        else
          return false, "Domain not in list '" .. tostring(listname) .. "'"
        end
      end,
      creates_dynamic_scope = true
    }
  end
end
