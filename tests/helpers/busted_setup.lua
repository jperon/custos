-- tests/helpers/busted_setup.lua
-- Helper chargé avant chaque suite Busted.
-- Injecte les stubs communs (ffi_defs, config, log) et les cdef POSIX
-- minimaux dont dépendent les modules de parsing en dehors de ffi_defs.
--
-- Patche aussi `require "filter.conditions.X"` pour que les objets enrichis
-- retournés exposent `__call = self.eval`. Permet aux specs historiques
-- d'invoquer `f(req)` plutôt que `f.eval(req)` sans toucher au code de prod.
--
-- IMPORTANT : ne pas re-déclarer de types/fonctions que ffi_defs.lua déclare
-- lui-même (pipe2, fcntl, close, read, write, inet_ntop, etc.) — LuaJIT
-- n'accepte pas les redéfinitions.  Seuls les symboles absents de ffi_defs
-- sont déclarés ici (ceux utilisés par les parsers avant que ffi_defs soit
-- chargé).

local ffi = require "ffi"

-- ── Stub ffi_defs ─────────────────────────────────────────────────────────
-- Empêche ffi_defs.lua de tenter de dlopen libnetfilter_queue / libnftables,
-- absentes de l'environnement de test unitaire.
-- Certaines specs (ffi_defs_spec) effacent ce stub pour tester le vrai module.
if not package.loaded["ffi_defs"] then
  package.loaded["ffi_defs"] = {
    ffi    = ffi,
    libc   = ffi.C,
    libnfq = {},
    libnft = {},
  }
end

-- ── cdef POSIX minimaux ────────────────────────────────────────────────────
-- Déclarations nécessaires aux parsers de paquets (nfq/packet, ipc…) quand
-- ffi_defs est stubbé et n'exécute donc pas ses propres cdef.
-- pcall → idempotent si un autre module les a déjà déclarées.
pcall(function()
  ffi.cdef [[
    typedef struct { long tv_sec; long tv_nsec; } timespec_t;
    const char* inet_ntop(int af, const void *src, char *dst, unsigned int size);
    int         inet_pton(int af, const char *src, void *dst);
    int         nanosleep(const timespec_t *req, timespec_t *rem);
  ]]
end)

-- ── Stub config ────────────────────────────────────────────────────────────
if not package.loaded["config"] then
  package.loaded["config"] = {
    PROTO_TCP       = 6,
    PROTO_UDP       = 17,
    AF_INET         = 2,
    AF_INET6        = 10,
    DNS_PORT        = 53,
    DOCKER_MODE     = false,
    ALLOWED_DOMAINS = {},
    IPC_PENDING_TTL = 5,
    CLIENT_EXPIRY   = 300,
    QUEUE_CAPTIVE   = 2,
    nft = {
      family  = "bridge",
      family6 = "bridge",
      table   = "dns-filter-bridge",
      set_ip4 = "ip4_allowed",
      set_ip6 = "ip6_allowed",
      set_mac4 = "mac4_allowed",
      set_mac6 = "mac6_allowed",
      ip_timeout = "2m",
    }
  }
end

-- ── Stub log ───────────────────────────────────────────────────────────────
if not package.loaded["log"] then
  local nop = function() end
  package.loaded["log"] = {
    log_debug = nop,
    log_warn  = nop,
    log_error = nop,
    log_info  = nop,
    now        = function() return os.time() end,
    get_log_level_num = function(level)
      return 0
    end,
  }
end

-- ── Stub nfq/ethernet ────────────────────────────────────────────────────
if not package.loaded["nfq/ethernet"] then
  package.loaded["nfq/ethernet"] = {
    get_l2         = function() return { mac_src="00:00:00:00:00:00", mac_dst="unknown",
                                         mac_raw="\0\0\0\0\0\0", in_ifindex=0, vlan=nil } end,
  }
end

-- ── Backward-compat : conditions appelables via __call ────────────────────
-- Le code de prod expose les conditions via objets enrichis (.eval). Les
-- specs historiques font `f = (cond cfg) arg ; v = f req`. On préserve cette
-- forme en wrappant le retour des factories pour ajouter __call → eval.
do
  local function make_callable(obj)
    if type(obj) == "table" and type(obj.eval) == "function" then
      if not obj.compile_nft then
        obj.compile_nft = function() return nil, "worker-only" end
      end
      if getmetatable(obj) == nil then
        setmetatable(obj, { __call = function(self, req) return self.eval(req) end })
      end
    end
    return obj
  end

  local function wrap_factory(outer)
    if type(outer) ~= "function" then return outer end
    return function(cfg)
      local inner = outer(cfg)
      if type(inner) ~= "function" then return inner end
      return function(args)
        return make_callable(inner(args))
      end
    end
  end

  local orig_require = require
  _G.require = function(name)
    local m = orig_require(name)
    if type(name) == "string"
       and (name:match("^filter%.conditions%.") or name:match("^filter%.actions%."))
    then
      if type(m) == "function" then
        -- Ancien format : module = factory function
        return wrap_factory(m)
      elseif type(m) == "table" and type(m.factory) == "function" then
        -- Nouveau format : module = { schema, factory }
        return { schema = m.schema, factory = wrap_factory(m.factory) }
      end
    end
    return m
  end
end
