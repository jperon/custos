local ffi = require("ffi")
local libc
libc = require("ffi_defs").libc
local bin48 = nil
local _xxh64 = nil
local _ensure_libs
_ensure_libs = function()
  if bin48 and _xxh64 then
    return true
  end
  local ok, xxhash = pcall(require, "ffi_xxhash")
  if not (ok) then
    return false
  end
  bin48 = require("filter.lib.bin48")
  _xxh64 = xxhash.xxh64
  return true
end
local PROT_READ = 0x1
local MAP_SHARED = 0x01
local O_RDONLY = 0
local SEEK_END = 2
local MAP_FAILED = ffi.cast("void*", -1)
local _mappings = { }
local CACHE_MAX_SIZE = 1000
local CACHE_TTL_SEC = 5
local _domain_cache = { }
local _cache_count = 0
local _cache_hits = 0
local _cache_misses = 0
local _NIL_LIST = "\0"
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
  _cache_count = 0
  _cache_hits = 0
  _cache_misses = 0
end
local _evict_if_needed
_evict_if_needed = function()
  if _cache_count <= CACHE_MAX_SIZE then
    return 
  end
  local target = math.floor(CACHE_MAX_SIZE / 2)
  local kept = 0
  for _, sub in pairs(_domain_cache) do
    for d in pairs(sub) do
      if kept >= target then
        sub[d] = nil
      else
        kept = kept + 1
      end
    end
  end
  _cache_count = kept
end
local load_list
load_list = function(path)
  if not (_ensure_libs()) then
    return nil, "ffi_xxhash non disponible"
  end
  if path:match("%.bin$") then
    local fd = libc.open(path, O_RDONLY, 0)
    if fd < 0 then
      return nil, "Cannot open " .. tostring(path)
    end
    local size = tonumber(libc.lseek(fd, 0, SEEK_END))
    if size <= 0 then
      libc.close(fd)
      return nil, "Empty bin file: " .. tostring(path)
    end
    local n = math.floor(size / 6)
    if n == 0 then
      libc.close(fd)
      return nil, "Empty bin file: " .. tostring(path)
    end
    local ptr = libc.mmap(nil, size, PROT_READ, MAP_SHARED, fd, 0)
    libc.close(fd)
    if ptr == MAP_FAILED then
      return nil, "mmap failed: " .. tostring(path)
    end
    ffi.gc(ptr, function(p)
      return libc.munmap(p, size)
    end)
    _mappings[#_mappings + 1] = ptr
    local arr = ffi.cast("const uint8_t*", ptr)
    return arr, n
  else
    local fh = io.open(path, "rb")
    if not (fh) then
      return nil, "Cannot open " .. tostring(path)
    end
    local data = fh:read("*a")
    fh:close()
    local domains = { }
    for line in data:gmatch("[^\n]+") do
      local domain = line:match("^%s*(.-)%s*$")
      domain = (domain:match("^([^#]*)")) or ""
      domain = domain:match("^%s*(.-)%s*$")
      if domain ~= "" then
        domains[#domains + 1] = domain
      end
    end
    local payload, n = bin48.pack_domains(domains)
    if n == 0 then
      return nil, "Empty domains file: " .. tostring(path)
    end
    _mappings[#_mappings + 1] = payload
    local arr = ffi.cast("const uint8_t*", payload)
    return arr, n
  end
end
local lookup
lookup = function(arr, n, domain, listname)
  local now = os.time()
  local lkey = listname or _NIL_LIST
  local sub = _domain_cache[lkey]
  if not (sub) then
    sub = { }
    _domain_cache[lkey] = sub
  end
  local cached = sub[domain]
  if cached and now - cached.ts < CACHE_TTL_SEC then
    _cache_hits = _cache_hits + 1
    return cached.found
  end
  _cache_misses = _cache_misses + 1
  local found = bin48.bsearch(arr, n, bin48.truncate(_xxh64(domain)))
  if not found then
    local pos = domain:find(".", 1, true)
    while pos do
      local suffix = domain:sub(pos + 1)
      if bin48.bsearch(arr, n, bin48.truncate(_xxh64(suffix))) then
        found = true
        break
      end
      pos = domain:find(".", pos + 1, true)
    end
  end
  if not (cached) then
    _cache_count = _cache_count + 1
    _evict_if_needed()
  end
  sub[domain] = {
    found = found,
    ts = now
  }
  return found
end
local _schema = {
  label = "Liste de domaines",
  description = "Domaine présent dans une liste compilée (.bin/.domains)",
  category = "destination",
  arg_type = "string",
  arg_hint = "ex: toulouse/malware",
  forms = {
    list = {
      label = "Groupe de listes (fichier nommé)",
      hint = "nom d'un fichier listant des domainlists, une par ligne",
      description = "Domaine présent dans l'une des domainlists nommées dans ce fichier-groupe"
    },
    lists = {
      label = "Plusieurs groupes de listes",
      hint = "un nom de fichier-groupe par ligne"
    }
  }
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
