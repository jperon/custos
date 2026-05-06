-- tests/helpers/busted_setup.lua
-- Helper chargé avant chaque suite Busted.
-- Injecte les stubs communs (ffi_defs, config, log) et les cdef POSIX
-- minimaux dont dépendent les modules de parsing en dehors de ffi_defs.
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
-- Déclarations nécessaires aux parsers de paquets (parse/ndpi, ipc…) quand
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
  }
end

-- ── Stub parse/ethernet ────────────────────────────────────────────────────
if not package.loaded["parse/ethernet"] then
  package.loaded["parse/ethernet"] = {
    get_l2         = function() return { mac_src="00:00:00:00:00:00", mac_dst="unknown",
                                         mac_raw="\0\0\0\0\0\0", in_ifindex=0, vlan=nil } end,
  }
end
