-- tests/helpers/busted_setup.lua
-- Helper chargé avant chaque suite Busted.
-- Injecte les stubs communs (ffi_defs, config, log) et les cdef POSIX
-- minimaux dont dépendent les modules de parsing.
--
-- Ne pas modifier sans mettre à jour les commentaires correspondants dans
-- tests/README.md.

local ffi = require "ffi"
local bit = require "bit"

-- ── Stubs ffi_defs ─────────────────────────────────────────────────────────
-- Empêche ffi_defs.lua de tenter de dlopen libnetfilter_queue / libnftables,
-- absentes de l'environnement de test unitaire.
if not package.loaded["ffi_defs"] then
  package.loaded["ffi_defs"] = {
    ffi    = ffi,
    libc   = ffi.C,
    libnfq = {},
    libnft = {},
  }
end

-- ── cdef POSIX minimaux ────────────────────────────────────────────────────
-- Les parsers de paquets (parse/ndpi, ipc…) utilisent inet_ntop/pton et
-- nanosleep. On les déclare ici une seule fois (pcall → safe si déjà déclarés).
pcall(function()
  ffi.cdef [[
    typedef struct { long tv_sec; long tv_nsec; } timespec_t;
    const char* inet_ntop(int af, const void *src, char *dst, unsigned int size);
    int         inet_pton(int af, const char *src, void *dst);
    int         nanosleep(const timespec_t *req, timespec_t *rem);
    int         pipe2(int pipefd[2], int flags);
    int         fcntl(int fd, int cmd, ...);
    int         close(int fd);
    ssize_t     read(int fd, void *buf, size_t count);
    ssize_t     write(int fd, const void *buf, size_t count);
  ]]
end)

-- ── Stub config ────────────────────────────────────────────────────────────
if not package.loaded["config"] then
  package.loaded["config"] = {
    PROTO_TCP      = 6,
    PROTO_UDP      = 17,
    AF_INET        = 2,
    AF_INET6       = 10,
    DNS_PORT       = 53,
    DOCKER_MODE    = false,
    ALLOWED_DOMAINS = {},
    IPC_PENDING_TTL = 5,
    CLIENT_EXPIRY  = 300,
    QUEUE_CAPTIVE  = 2,
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
    format_mac     = function() return "00:00:00:00:00:00" end,
    format_mac_ptr = function() return "00:00:00:00:00:00" end,
  }
end
