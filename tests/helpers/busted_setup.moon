-- tests/helpers/busted_setup.moon
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

ffi = require "ffi"

-- ── Stub ffi_defs ─────────────────────────────────────────────────────────
-- Empêche ffi_defs.lua de tenter de dlopen libnetfilter_queue / libnftables,
-- absentes de l'environnement de test unitaire.
-- Certaines specs (ffi_defs_spec) effacent ce stub pour tester le vrai module.
unless package.loaded["ffi_defs"]
  package.loaded["ffi_defs"] = {
    :ffi
    libc:   ffi.C
    libnfq: {}
    libnft: {}
  }

-- ── cdef POSIX minimaux ────────────────────────────────────────────────────
-- Déclarations nécessaires aux parsers de paquets (nfq/packet, ipc…) quand
-- ffi_defs est stubbé et n'exécute donc pas ses propres cdef.
-- pcall → idempotent si un autre module les a déjà déclarées.
pcall ->
  ffi.cdef [[
    typedef struct { long tv_sec; long tv_nsec; } timespec_t;
    const char* inet_ntop(int af, const void *src, char *dst, unsigned int size);
    int         inet_pton(int af, const char *src, void *dst);
    int         nanosleep(const timespec_t *req, timespec_t *rem);
  ]]

-- mmap/open/lseek pour le chargement des listes .bin (to_domainlist). Bloc
-- séparé : un échec (symbole déjà déclaré) ne doit pas empêcher les autres.
pcall ->
  ffi.cdef [[
    int     open(const char *path, int flags, ...);
    int     close(int fd);
    long    lseek(int fd, long offset, int whence);
    void*   mmap(void *addr, unsigned long length, int prot, int flags, int fd, long offset);
    int     munmap(void *addr, unsigned long length);
  ]]

-- ── Stub config ────────────────────────────────────────────────────────────
unless package.loaded["config"]
  package.loaded["config"] = {
    PROTO_TCP:       6
    PROTO_UDP:       17
    AF_INET:         2
    AF_INET6:        10
    DNS_PORT:        53
    DOCKER_MODE:     false
    ALLOWED_DOMAINS: {}
    IPC_PENDING_TTL: 5
    CLIENT_EXPIRY:   300
    QUEUE_CAPTIVE:   2
    nft: {
      family:  "bridge"
      family6: "bridge"
      table:   "dns-filter-bridge"
      set_ip4: "ip4_allowed"
      set_ip6: "ip6_allowed"
      set_mac4: "mac4_allowed"
      set_mac6: "mac6_allowed"
      ip_timeout: "2m"
    }
  }

-- ── Stub log ───────────────────────────────────────────────────────────────
-- Mock strict : vérifie que les fonctions de log reçoivent bien des thunks
-- (functions) et non des tables (erreur de migration eager -> lazy).
-- Cf. log.moon : la nouvelle API exige `log_xxx -> { ... }`.
unless package.loaded["log"]
  make_logger = (name) ->
    (thunk) ->
      if type(thunk) != "function"
        error "log_#{name} attend un thunk (function), reçu: #{type thunk}"
      -- Appeler le thunk pour valider qu'il retourne une table
      fields = thunk!
      if fields != nil and type(fields) != "table"
        error "log_#{name} thunk doit retourner une table ou nil, reçu: #{type fields}"

  package.loaded["log"] = {
    log_debug: make_logger "debug"
    log_warn:  make_logger "warn"
    log_error: make_logger "error"
    log_info:  make_logger "info"
    log_allow: make_logger "allow"
    log_block: make_logger "block"
    log_trace: make_logger "trace"
    now: -> os.time!
    get_log_level_num: (level) -> 0
    set_action_prefix: (prefix) -> nil
  }

-- ── Stub nfq/ethernet ────────────────────────────────────────────────────
unless package.loaded["nfq/ethernet"]
  package.loaded["nfq/ethernet"] = {
    get_l2: -> {
      mac_src:    "00:00:00:00:00:00"
      mac_dst:    "unknown"
      mac_raw:    "\0\0\0\0\0\0"
      in_ifindex: 0
      vlan:       nil
    }
  }

-- ── Backward-compat : conditions appelables via __call ────────────────────
-- Le code de prod expose les conditions via objets enrichis (.eval). Les
-- specs historiques font `f = (cond cfg) arg ; v = f req`. On préserve cette
-- forme en wrappant le retour des factories pour ajouter __call → eval.
do
  make_callable = (obj) ->
    if type(obj) == "table" and type(obj.eval) == "function"
      unless obj.compile_nft
        obj.compile_nft = -> nil, "worker-only"
      if getmetatable(obj) == nil
        setmetatable obj, { __call: (self, req) -> self.eval req
        }
    obj

  wrap_factory = (outer) ->
    return outer unless type(outer) == "function"
    (cfg) ->
      inner = outer cfg
      return inner unless type(inner) == "function"
      (args) -> make_callable inner args

  orig_require = require
  _G.require = (name) ->
    m = orig_require name
    if type(name) == "string" and
       (name\match("^filter%.conditions%.") or name\match("^filter%.actions%."))
      if type(m) == "function"
        -- Ancien format : module = factory function
        return wrap_factory m
      elseif type(m) == "table" and type(m.factory) == "function"
        -- Nouveau format : module = { schema, factory }
        return { schema: m.schema, factory: wrap_factory m.factory }
    m
