local ffi = require("ffi")
if not (package.loaded["ffi_defs"]) then
  package.loaded["ffi_defs"] = {
    ffi = ffi,
    libc = ffi.C,
    libnfq = { },
    libnft = { }
  }
end
pcall(function()
  return ffi.cdef([[    typedef struct { long tv_sec; long tv_nsec; } timespec_t;
    const char* inet_ntop(int af, const void *src, char *dst, unsigned int size);
    int         inet_pton(int af, const char *src, void *dst);
    int         nanosleep(const timespec_t *req, timespec_t *rem);
  ]])
end)
pcall(function()
  return ffi.cdef([[    int     open(const char *path, int flags, ...);
    int     close(int fd);
    long    lseek(int fd, long offset, int whence);
    void*   mmap(void *addr, unsigned long length, int prot, int flags, int fd, long offset);
    int     munmap(void *addr, unsigned long length);
  ]])
end)
if not (package.loaded["config"]) then
  package.loaded["config"] = {
    PROTO_TCP = 6,
    PROTO_UDP = 17,
    AF_INET = 2,
    AF_INET6 = 10,
    DNS_PORT = 53,
    DOCKER_MODE = false,
    ALLOWED_DOMAINS = { },
    IPC_PENDING_TTL = 5,
    CLIENT_EXPIRY = 300,
    QUEUE_CAPTIVE = 2,
    nft = {
      family = "bridge",
      family6 = "bridge",
      table = "dns-filter-bridge",
      set_ip4 = "ip4_allowed",
      set_ip6 = "ip6_allowed",
      set_mac4 = "mac4_allowed",
      set_mac6 = "mac6_allowed",
      ip_timeout = "2m"
    }
  }
end
if not (package.loaded["log"]) then
  local make_logger
  make_logger = function(name)
    return function(thunk)
      if type(thunk) ~= "function" then
        error("log_" .. tostring(name) .. " attend un thunk (function), reçu: " .. tostring(type(thunk)))
      end
      local fields = thunk()
      if fields ~= nil and type(fields) ~= "table" then
        return error("log_" .. tostring(name) .. " thunk doit retourner une table ou nil, reçu: " .. tostring(type(fields)))
      end
    end
  end
  package.loaded["log"] = {
    log_debug = make_logger("debug"),
    log_warn = make_logger("warn"),
    log_error = make_logger("error"),
    log_info = make_logger("info"),
    log_allow = make_logger("allow"),
    log_block = make_logger("block"),
    log_trace = make_logger("trace"),
    now = function()
      return os.time()
    end,
    get_log_level_num = function(level)
      return 0
    end,
    set_action_prefix = function(prefix)
      return nil
    end
  }
end
if not (package.loaded["nfq/ethernet"]) then
  package.loaded["nfq/ethernet"] = {
    get_l2 = function()
      return {
        mac_src = "00:00:00:00:00:00",
        mac_dst = "unknown",
        mac_raw = "\0\0\0\0\0\0",
        in_ifindex = 0,
        vlan = nil
      }
    end
  }
end
do
  local make_callable
  make_callable = function(obj)
    if type(obj) == "table" and type(obj.eval) == "function" then
      if not (obj.compile_nft) then
        obj.compile_nft = function()
          return nil, "worker-only"
        end
      end
      if getmetatable(obj) == nil then
        setmetatable(obj, {
          __call = function(self, req)
            return self.eval(req)
          end
        })
      end
    end
    return obj
  end
  local wrap_factory
  wrap_factory = function(outer)
    if not (type(outer) == "function") then
      return outer
    end
    return function(cfg)
      local inner = outer(cfg)
      if not (type(inner) == "function") then
        return inner
      end
      return function(args)
        return make_callable(inner(args))
      end
    end
  end
  local orig_require = require
  _G.require = function(name)
    local m = orig_require(name)
    if type(name) == "string" and (name:match("^filter%.conditions%.") or name:match("^filter%.actions%.")) then
      if type(m) == "function" then
        return wrap_factory(m)
      elseif type(m) == "table" and type(m.factory) == "function" then
        return {
          schema = m.schema,
          factory = wrap_factory(m.factory)
        }
      end
    end
    return m
  end
end
