local ffi = require("ffi")
local CACHE_MAX_SIZE = 1000
local CACHE_TTL_SEC = 5
local _domain_cache = { }
local _domain_cache_order = { }
local _cache_hits = 0
local _cache_misses = 0
local get_cache_stats
get_cache_stats = function()
  return {
    hits = _cache_hits,
    misses = _cache_misses
  }
end
local clear_cache
clear_cache = function()
  _domain_cache = { }
  _domain_cache_order = { }
  _cache_hits = 0
  _cache_misses = 0
end
local _evict_oldest_if_needed
_evict_oldest_if_needed = function()
  while #_domain_cache_order >= CACHE_MAX_SIZE do
    local oldest = table.remove(_domain_cache_order, 1)
    if oldest then
      _domain_cache[oldest] = nil
    end
  end
end
local load_list
load_list = function(path)
  local xxhash_ok, xxhash = pcall(require, "ffi_xxhash")
  if not (xxhash_ok) then
    return nil, "ffi_xxhash non disponible"
  end
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
lookup = function(arr, n, domain, listname)
  local xxh64
  xxh64 = require("ffi_xxhash").xxh64
  local bsearch
  bsearch = require("filter.lib.bsearch").bsearch
  local now = os.time()
  local cache_key = listname and tostring(listname) .. ":" .. tostring(domain) or domain
  local cached = _domain_cache[cache_key]
  if cached then
    if now - cached.ts < CACHE_TTL_SEC then
      _cache_hits = _cache_hits + 1
      return cached.found
    else
      _domain_cache[cache_key] = nil
      for i, d in ipairs(_domain_cache_order) do
        if d == cache_key then
          table.remove(_domain_cache_order, i)
          break
        end
      end
    end
  end
  _cache_misses = _cache_misses + 1
  local found = bsearch(arr, n, xxh64(domain))
  if not found then
    local pos = domain:find(".", 1, true)
    while pos do
      local suffix = domain:sub(pos + 1)
      if bsearch(arr, n, xxh64(suffix)) then
        found = true
        break
      end
      pos = domain:find(".", pos + 1, true)
    end
  end
  _evict_oldest_if_needed()
  _domain_cache[cache_key] = {
    found = found,
    ts = now
  }
  _domain_cache_order[#_domain_cache_order + 1] = cache_key
  return found
end
local _schema = {
  label = "Liste de domaines",
  description = "Domaine présent dans une liste compilée (.bin/.domains)",
  category = "destination",
  arg_type = "string",
  arg_hint = "ex: toulouse/malware"
}
local _factory
_factory = function(cfg)
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
        if lookup(arr, n, domain, listname) then
          return true, "Domain matched in list '" .. tostring(listname) .. "'"
        else
          return false, "Domain not in list '" .. tostring(listname) .. "'"
        end
      end,
      creates_dynamic_scope = true
    }
  end
end
return {
  schema = _schema,
  factory = _factory
}
