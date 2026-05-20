local ffi = require("ffi")
pcall(function()
  return ffi.cdef([[    typedef unsigned int socklen_t;
    struct sockaddr     { unsigned short sa_family; char sa_data[14]; };
    struct sockaddr_un  { unsigned short sun_family; char sun_path[108]; };
    int    socket(int domain, int type, int protocol);
    int    close(int fd);
    int    connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    long   send(int sockfd, const void *buf, unsigned long len, int flags);
    long   recv(int sockfd, void *buf, unsigned long len, int flags);
    int   *__errno_location(void);
  ]])
end)
do
  local cfg = package.loaded["config"]
  cfg.MAC_LEARNER_QUERY_SOCK = cfg.MAC_LEARNER_QUERY_SOCK or "/nonexistent/custos/mac_query.sock"
end
package.loaded["mac_learner_ipc"] = nil
local mac_learner_ipc = require("mac_learner_ipc")
local mac_from_eui64 = mac_learner_ipc.mac_from_eui64
local get_mac = mac_learner_ipc.get_mac
return describe("parse/mac_learner", function()
  describe("mac_from_eui64", function()
    it("adresse globale EUI-64 → MAC correcte", function()
      local mac = mac_from_eui64("fd00:28::6e1c:71ff:fe2f:76f1")
      return assert.equals("6c:1c:71:2f:76:f1", mac)
    end)
    it("adresse link-local EUI-64 → MAC correcte", function()
      local mac = mac_from_eui64("fe80::6e1c:71ff:fe2f:76f1")
      return assert.equals("6c:1c:71:2f:76:f1", mac)
    end)
    it("bit U/L inversé — premier octet pair (02 → 00)", function()
      local mac = mac_from_eui64("fe80::211:22ff:fe33:4455")
      return assert.equals("00:11:22:33:44:55", mac)
    end)
    it("bit U/L inversé — premier octet impair (03 → 01)", function()
      local mac = mac_from_eui64("fe80::323:45ff:fe67:89ab")
      return assert.equals("01:23:45:67:89:ab", mac)
    end)
    it("adresse non-EUI-64 courte (pas de ff:fe) → nil", function()
      local mac = mac_from_eui64("fd00::1")
      return assert.is_nil(mac)
    end)
    it("privacy extension (identifiant aléatoire sans ff:fe) → nil", function()
      local mac = mac_from_eui64("2001:db8::1a2b:3c4d:5e6f:7a8b")
      return assert.is_nil(mac)
    end)
    it("adresse IPv4 → nil", function()
      local mac = mac_from_eui64("192.168.1.1")
      return assert.is_nil(mac)
    end)
    it("nil → nil", function()
      local mac = mac_from_eui64(nil)
      return assert.is_nil(mac)
    end)
    it("chaîne vide → nil", function()
      local mac = mac_from_eui64("")
      return assert.is_nil(mac)
    end)
    return it("chaîne invalide (ni IPv4 ni IPv6 parsable) → nil", function()
      local mac = mac_from_eui64("not-an-address")
      return assert.is_nil(mac)
    end)
  end)
  describe("get_mac", function()
    it("nil → \"unknown\"", function()
      return assert.equals("unknown", get_mac(nil))
    end)
    it("chaîne vide → \"unknown\"", function()
      return assert.equals("unknown", get_mac(""))
    end)
    it("\"unknown\" → \"unknown\"", function()
      return assert.equals("unknown", get_mac("unknown"))
    end)
    it("adresse EUI-64 (pas de learner) → MAC via fallback EUI-64", function()
      local mac = get_mac("fe80::211:22ff:fe33:4455")
      return assert.equals("00:11:22:33:44:55", mac)
    end)
    it("adresse IPv6 non-EUI-64 (pas de learner) → \"unknown\"", function()
      local mac = get_mac("2001:db8::1")
      return assert.equals("unknown", mac)
    end)
    return it("adresse IPv4 (pas de learner) → \"unknown\"", function()
      local mac = get_mac("10.0.0.1")
      return assert.equals("unknown", mac)
    end)
  end)
  describe("mac_from_eui64 inet_pton failure", function()
    it("chaîne avec ':' mais IPv6 invalide → inet_pton retourne 0 → nil", function()
      local mac = mac_from_eui64("not:a:valid:v6addr:xyz")
      return assert.is_nil(mac)
    end)
    return it("chaîne '::-' invalide → nil", function()
      local mac = mac_from_eui64("zz::gg::hh")
      return assert.is_nil(mac)
    end)
  end)
  describe("get_mac avec learner actif", function()
    local SOCK_PATH = "./tmp/test_mac_ipc_query.sock"
    local server_pid = nil
    local un_family_size = ffi.sizeof(ffi.typeof("struct sockaddr_un")) - 108
    local compatible_layout = (un_family_size == 2)
    local start_server
    start_server = function(response, max_conns)
      max_conns = max_conns or 5
      local script = "./tmp/mac_server_test.lua"
      local fh = io.open(script, "w")
      fh:write([=[local ffi = require "ffi"
ffi.cdef[[
typedef unsigned int socklen_t;
struct sockaddr { unsigned short sa_family; char sa_data[14]; };
struct sockaddr_un { unsigned short sun_family; char sun_path[108]; };
int socket(int domain, int type, int protocol);
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int listen(int sockfd, int backlog);
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
long send(int sockfd, const void *buf, unsigned long len, int flags);
int close(int fd);
int unlink(const char *pathname);
]]
local path, response, max_conns = arg[1], arg[2] or "", tonumber(arg[3]) or 5
local AF_UNIX, SOCK_STREAM = 1, 1
ffi.C.unlink(path)
local fd = ffi.C.socket(AF_UNIX, SOCK_STREAM, 0)
if fd < 0 then os.exit(1) end
local addr = ffi.new("struct sockaddr_un")
addr.sun_family = AF_UNIX
ffi.copy(addr.sun_path, path, #path)
local addrlen = ffi.offsetof("struct sockaddr_un", "sun_path") + #path + 1
if ffi.C.bind(fd, ffi.cast("const struct sockaddr *", addr), addrlen) ~= 0 then ffi.C.close(fd); os.exit(1) end
if ffi.C.listen(fd, 8) ~= 0 then ffi.C.close(fd); os.exit(1) end
for _ = 1, max_conns do
  local c = ffi.C.accept(fd, nil, nil)
  if c >= 0 then
    if #response > 0 then ffi.C.send(c, response, #response, 0) end
    ffi.C.close(c)
  end
end
ffi.C.close(fd)
ffi.C.unlink(path)
]=])
      fh:close()
      os.execute("rm -f " .. SOCK_PATH)
      local pid_file = SOCK_PATH .. ".pid"
      os.execute(string.format("luajit %s %s %s %d >/dev/null 2>&1 & echo $! > %s", script, string.format("%q", SOCK_PATH), string.format("%q", response), max_conns, pid_file))
      for i = 1, 40 do
        if os.execute("test -S " .. SOCK_PATH) then
          os.execute("sleep 1")
          break
        end
        os.execute("sleep 1")
      end
      local fh_pid = io.open(pid_file, "r")
      local pid = 0
      if fh_pid then
        pid = tonumber(fh_pid:read("*l")) or 0
        fh_pid:close()
        os.remove(pid_file)
      end
      return pid
    end
    local stop_server
    stop_server = function(pid)
      os.execute("kill " .. tostring(pid) .. " 2>/dev/null; true")
      return os.remove(SOCK_PATH)
    end
    before_each(function()
      package.loaded["mac_learner_ipc"] = nil
      local cfg = package.loaded["config"]
      cfg.MAC_LEARNER_QUERY_SOCK = SOCK_PATH
    end)
    after_each(function()
      if server_pid then
        stop_server(server_pid)
      end
      server_pid = nil
      local cfg = package.loaded["config"]
      cfg.MAC_LEARNER_QUERY_SOCK = "/nonexistent/custos/mac_query.sock"
      package.loaded["mac_learner_ipc"] = nil
    end)
    it("learner répond avec un MAC valide → retourne ce MAC", function()
      if not (compatible_layout) then
        pending("struct sockaddr_un incompatible (sa_family_t=uint32 de socket.lua)")
      end
      server_pid = start_server("aa:bb:cc:dd:ee:ff", 3)
      local m = require("mac_learner_ipc")
      local result = m.get_mac("10.0.0.1")
      return assert.equals("aa:bb:cc:dd:ee:ff", result)
    end)
    it("learner répond avec MAC invalide + IP non-EUI-64 → \"unknown\"", function()
      if not (compatible_layout) then
        pending("struct sockaddr_un incompatible (sa_family_t=uint32 de socket.lua)")
      end
      server_pid = start_server("INVALID_RESPONSE", 3)
      local m = require("mac_learner_ipc")
      local result = m.get_mac("10.0.0.1")
      return assert.equals("unknown", result)
    end)
    return it("learner répond avec MAC invalide + IP EUI-64 → MAC via fallback", function()
      if not (compatible_layout) then
        pending("struct sockaddr_un incompatible (sa_family_t=uint32 de socket.lua)")
      end
      server_pid = start_server("INVALID", 3)
      local m = require("mac_learner_ipc")
      local result = m.get_mac("fe80::211:22ff:fe33:4455")
      return assert.equals("00:11:22:33:44:55", result)
    end)
  end)
  describe("get_mac recv vide (n <= 0)", function()
    local SOCK_PATH2 = "./tmp/test_mac_ipc_empty.sock"
    local server_pid2 = nil
    local un_family_size2 = ffi.sizeof(ffi.typeof("struct sockaddr_un")) - 108
    local compatible2 = (un_family_size2 == 2)
    before_each(function()
      package.loaded["mac_learner_ipc"] = nil
      local cfg = package.loaded["config"]
      cfg.MAC_LEARNER_QUERY_SOCK = SOCK_PATH2
    end)
    after_each(function()
      if server_pid2 then
        os.execute("kill " .. tostring(server_pid2) .. " 2>/dev/null; true")
      end
      os.remove(SOCK_PATH2)
      server_pid2 = nil
      local cfg = package.loaded["config"]
      cfg.MAC_LEARNER_QUERY_SOCK = "/nonexistent/custos/mac_query.sock"
      package.loaded["mac_learner_ipc"] = nil
    end)
    return it("learner ferme connexion sans données → \"unknown\"", function()
      if not (compatible2) then
        pending("struct sockaddr_un incompatible (sa_family_t=uint32 de socket.lua)")
      end
      os.execute("rm -f " .. SOCK_PATH2)
      local script = "./tmp/mac_server_empty.lua"
      local fh_script = io.open(script, "w")
      fh_script:write([=[local ffi = require "ffi"
ffi.cdef[[
typedef unsigned int socklen_t;
struct sockaddr { unsigned short sa_family; char sa_data[14]; };
struct sockaddr_un { unsigned short sun_family; char sun_path[108]; };
int socket(int domain, int type, int protocol);
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int listen(int sockfd, int backlog);
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int close(int fd);
int unlink(const char *pathname);
]]
local path, max_conns = arg[1], tonumber(arg[2]) or 3
local AF_UNIX, SOCK_STREAM = 1, 1
ffi.C.unlink(path)
local fd = ffi.C.socket(AF_UNIX, SOCK_STREAM, 0)
if fd < 0 then os.exit(1) end
local addr = ffi.new("struct sockaddr_un")
addr.sun_family = AF_UNIX
ffi.copy(addr.sun_path, path, #path)
local addrlen = ffi.offsetof("struct sockaddr_un", "sun_path") + #path + 1
if ffi.C.bind(fd, ffi.cast("const struct sockaddr *", addr), addrlen) ~= 0 then ffi.C.close(fd); os.exit(1) end
if ffi.C.listen(fd, 8) ~= 0 then ffi.C.close(fd); os.exit(1) end
for _ = 1, max_conns do
  local c = ffi.C.accept(fd, nil, nil)
  if c >= 0 then ffi.C.close(c) end
end
ffi.C.close(fd)
ffi.C.unlink(path)
]=])
      fh_script:close()
      local cmd = string.format("luajit %s %s 3 >/dev/null 2>&1 & echo $!", script, string.format("%q", SOCK_PATH2))
      local fh = io.popen(cmd)
      local pid_str = fh:read("*l")
      fh:close()
      server_pid2 = tonumber(pid_str)
      for i = 1, 20 do
        if os.execute("test -S " .. SOCK_PATH2) then
          os.execute("sleep 1")
          break
        end
        os.execute("sleep 1")
      end
      local m = require("mac_learner_ipc")
      local result = m.get_mac("10.0.0.1")
      return assert.equals("unknown", result)
    end)
  end)
  return describe("get_mac mock libc", function()
    local make_mock_libc
    make_mock_libc = function()
      return {
        socket = function(a, b, c)
          return ffi.C.socket(a, b, c)
        end,
        close = function(fd)
          return ffi.C.close(fd)
        end,
        connect = function(s, a, l)
          return ffi.C.connect(s, a, l)
        end,
        send = function(s, b, n, f)
          return ffi.C.send(s, b, n, f)
        end,
        recv = function(s, b, n, f)
          return ffi.C.recv(s, b, n, f)
        end,
        inet_pton = function(af, src, d)
          return ffi.C.inet_pton(af, src, d)
        end,
        __errno_location = function()
          return ffi.C.__errno_location()
        end
      }
    end
    local orig_ffi_defs = nil
    local mock_libc = nil
    before_each(function()
      orig_ffi_defs = package.loaded["ffi_defs"]
      mock_libc = make_mock_libc()
      package.loaded["ffi_defs"] = {
        ffi = ffi,
        libc = mock_libc,
        libnfq = { },
        libnft = { }
      }
      package.loaded["mac_learner_ipc"] = nil
      local cfg = package.loaded["config"]
      cfg.MAC_LEARNER_QUERY_SOCK = "/nonexistent/sock"
    end)
    after_each(function()
      package.loaded["ffi_defs"] = orig_ffi_defs
      package.loaded["mac_learner_ipc"] = nil
      mock_libc = nil
    end)
    it("socket() retourne -1 → log_warn + fallback EUI-64 ou unknown", function()
      local log_calls = { }
      local old_log = package.loaded["log"]
      package.loaded["log"] = {
        log_warn = function(x)
          log_calls[#log_calls + 1] = x
        end
      }
      mock_libc.socket = function()
        return -1
      end
      local m = require("mac_learner_ipc")
      local result = m.get_mac("10.0.0.1")
      assert.equals("unknown", result)
      assert.equals(1, #log_calls)
      assert.equals("mac_ipc_socket_failed", log_calls[1].action)
      package.loaded["log"] = old_log
    end)
    it("socket() retourne -1 + IP EUI-64 → fallback EUI-64", function()
      package.loaded["log"] = {
        log_warn = function(x)
          return nil
        end
      }
      mock_libc.socket = function()
        return -1
      end
      local m = require("mac_learner_ipc")
      local result = m.get_mac("fe80::211:22ff:fe33:4455")
      return assert.equals("00:11:22:33:44:55", result)
    end)
    it("connect réussi + recv MAC valide → retourne MAC", function()
      pcall(function()
        return ffi.cdef("int socketpair(int domain, int type, int protocol, int sv[2]);")
      end)
      local sv = ffi.new("int[2]")
      local rc = ffi.C.socketpair(1, 1, 0, sv)
      if not (rc == 0) then
        pending("socketpair non disponible")
      end
      local mac_resp = "aa:bb:cc:dd:ee:ff"
      ffi.C.send(sv[1], mac_resp, #mac_resp, 0)
      ffi.C.close(sv[1])
      local client_fd = sv[0]
      mock_libc.socket = function()
        return client_fd
      end
      mock_libc.connect = function(s, a, l)
        return 0
      end
      mock_libc.send = function(s, b, n, f)
        return n
      end
      local m = require("mac_learner_ipc")
      local result = m.get_mac("10.0.0.1")
      return assert.equals("aa:bb:cc:dd:ee:ff", result)
    end)
    it("connect réussi + recv réponse invalide + non-EUI-64 → unknown", function()
      pcall(function()
        return ffi.cdef("int socketpair(int domain, int type, int protocol, int sv[2]);")
      end)
      local sv = ffi.new("int[2]")
      local rc = ffi.C.socketpair(1, 1, 0, sv)
      if not (rc == 0) then
        pending("socketpair non disponible")
      end
      local resp = "NOT_A_MAC"
      ffi.C.send(sv[1], resp, #resp, 0)
      ffi.C.close(sv[1])
      local client_fd = sv[0]
      mock_libc.socket = function()
        return client_fd
      end
      mock_libc.connect = function(s, a, l)
        return 0
      end
      mock_libc.send = function(s, b, n, f)
        return n
      end
      local m = require("mac_learner_ipc")
      local result = m.get_mac("10.0.0.1")
      return assert.equals("unknown", result)
    end)
    it("connect réussi + recv réponse invalide + IP EUI-64 → MAC via EUI-64", function()
      pcall(function()
        return ffi.cdef("int socketpair(int domain, int type, int protocol, int sv[2]);")
      end)
      local sv = ffi.new("int[2]")
      local rc = ffi.C.socketpair(1, 1, 0, sv)
      if not (rc == 0) then
        pending("socketpair non disponible")
      end
      local resp = "INVALID_MAC"
      ffi.C.send(sv[1], resp, #resp, 0)
      ffi.C.close(sv[1])
      local client_fd = sv[0]
      mock_libc.socket = function()
        return client_fd
      end
      mock_libc.connect = function(s, a, l)
        return 0
      end
      mock_libc.send = function(s, b, n, f)
        return n
      end
      local m = require("mac_learner_ipc")
      local result = m.get_mac("fe80::211:22ff:fe33:4455")
      return assert.equals("00:11:22:33:44:55", result)
    end)
    return it("connect réussi + recv retourne 0 (connexion fermée) → unknown", function()
      pcall(function()
        return ffi.cdef("int socketpair(int domain, int type, int protocol, int sv[2]);")
      end)
      local sv = ffi.new("int[2]")
      local rc = ffi.C.socketpair(1, 1, 0, sv)
      if not (rc == 0) then
        pending("socketpair non disponible")
      end
      ffi.C.close(sv[1])
      local client_fd = sv[0]
      mock_libc.socket = function()
        return client_fd
      end
      mock_libc.connect = function(s, a, l)
        return 0
      end
      mock_libc.send = function(s, b, n, f)
        return n
      end
      local m = require("mac_learner_ipc")
      local result = m.get_mac("10.0.0.1")
      return assert.equals("unknown", result)
    end)
  end)
end)
