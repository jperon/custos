-- tests/unit/parse/mac_learner_spec.moon
-- Spec Busted pour mac_learner_ipc : mac_from_eui64 et get_mac.
-- MoonScript → Lua, runner Busted 2.3.0 --lua=luajit.
--
-- Stubs injectés par tests/helpers/busted_setup.lua :
--   ffi_defs (ffi + libc = ffi.C), config, log.
--
-- Ce fichier ajoute les cdef manquants (sockaddr_un, socket, connect…)
-- dont ffi_defs.lua serait normalement responsable mais que le stub n'injecte pas.

ffi = require "ffi"

-- ── cdef supplémentaires nécessaires à mac_learner_ipc ────────────────────
-- On utilise pcall pour rester idempotent si d'autres specs les ont déjà déclarés.
pcall ->
  ffi.cdef [[
    typedef unsigned int socklen_t;
    struct sockaddr     { unsigned short sa_family; char sa_data[14]; };
    struct sockaddr_un  { unsigned short sun_family; char sun_path[108]; };
    int    socket(int domain, int type, int protocol);
    int    close(int fd);
    int    connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    long   send(int sockfd, const void *buf, unsigned long len, int flags);
    long   recv(int sockfd, void *buf, unsigned long len, int flags);
    int   *__errno_location(void);
  ]]

-- ── Stub config : ajouter MAC_LEARNER_QUERY_SOCK si absent ────────────────
-- busted_setup.lua crée le stub config sans cette clé.
do
  cfg = package.loaded["config"]
  cfg.MAC_LEARNER_QUERY_SOCK = cfg.MAC_LEARNER_QUERY_SOCK or "/nonexistent/custos/mac_query.sock"

-- ── Chargement du module ──────────────────────────────────────────────────
package.loaded["mac_learner_ipc"] = nil
mac_learner_ipc = require "mac_learner_ipc"
mac_from_eui64  = mac_learner_ipc.mac_from_eui64
get_mac         = mac_learner_ipc.get_mac

-- ─────────────────────────────────────────────────────────────────────────
describe "parse/mac_learner", ->

  -- ── mac_from_eui64 ──────────────────────────────────────────────────────

  describe "mac_from_eui64", ->

    it "adresse globale EUI-64 → MAC correcte", ->
      -- MAC  6c:1c:71:2f:76:f1
      -- EUI-64 : flip U/L bit (6c→6e), insert ff:fe
      --   6e:1c:71:ff:fe:2f:76:f1
      -- IPv6 globale : fd00:28::6e1c:71ff:fe2f:76f1
      mac = mac_from_eui64 "fd00:28::6e1c:71ff:fe2f:76f1"
      assert.equals "6c:1c:71:2f:76:f1", mac

    it "adresse link-local EUI-64 → MAC correcte", ->
      -- Même vecteur, adresse link-local
      mac = mac_from_eui64 "fe80::6e1c:71ff:fe2f:76f1"
      assert.equals "6c:1c:71:2f:76:f1", mac

    it "bit U/L inversé — premier octet pair (02 → 00)", ->
      -- MAC 00:11:22:33:44:55 → EUI-64 : flip U/L (00→02), insert ff:fe
      --   02:11:22:ff:fe:33:44:55
      -- IPv6 : fe80::211:22ff:fe33:4455
      mac = mac_from_eui64 "fe80::211:22ff:fe33:4455"
      assert.equals "00:11:22:33:44:55", mac

    it "bit U/L inversé — premier octet impair (03 → 01)", ->
      -- MAC 01:23:45:67:89:ab → EUI-64 : flip U/L (01→03), insert ff:fe
      --   03:23:45:ff:fe:67:89:ab
      -- IPv6 : fe80::323:45ff:fe67:89ab
      mac = mac_from_eui64 "fe80::323:45ff:fe67:89ab"
      assert.equals "01:23:45:67:89:ab", mac

    it "adresse non-EUI-64 courte (pas de ff:fe) → nil", ->
      -- fd00::1 n'a pas d'identifiant EUI-64
      mac = mac_from_eui64 "fd00::1"
      assert.is_nil mac

    it "privacy extension (identifiant aléatoire sans ff:fe) → nil", ->
      -- Octets 11-12 ne sont pas 0xff/0xfe
      mac = mac_from_eui64 "2001:db8::1a2b:3c4d:5e6f:7a8b"
      assert.is_nil mac

    it "adresse IPv4 → nil", ->
      -- Pas de ':' → rejeté immédiatement
      mac = mac_from_eui64 "192.168.1.1"
      assert.is_nil mac

    it "nil → nil", ->
      mac = mac_from_eui64 nil
      assert.is_nil mac

    it "chaîne vide → nil", ->
      -- Pas de ':' → rejeté
      mac = mac_from_eui64 ""
      assert.is_nil mac

    it "chaîne invalide (ni IPv4 ni IPv6 parsable) → nil", ->
      mac = mac_from_eui64 "not-an-address"
      assert.is_nil mac

  -- ── get_mac ─────────────────────────────────────────────────────────────

  describe "get_mac", ->

    -- Le socket IPC pointe vers /nonexistent/... donc connect() échoue
    -- immédiatement : get_mac tombe sur le fallback EUI-64 ou "unknown".

    it "nil → \"unknown\"", ->
      assert.equals "unknown", get_mac(nil)

    it "chaîne vide → \"unknown\"", ->
      assert.equals "unknown", get_mac("")

    it "\"unknown\" → \"unknown\"", ->
      assert.equals "unknown", get_mac("unknown")

    it "adresse EUI-64 (pas de learner) → MAC via fallback EUI-64", ->
      -- Le connect échoue → fallback mac_from_eui64
      mac = get_mac "fe80::211:22ff:fe33:4455"
      assert.equals "00:11:22:33:44:55", mac

    it "adresse IPv6 non-EUI-64 (pas de learner) → \"unknown\"", ->
      -- connect échoue, mac_from_eui64 retourne nil → "unknown"
      mac = get_mac "2001:db8::1"
      assert.equals "unknown", mac

    it "adresse IPv4 (pas de learner) → \"unknown\"", ->
      -- inet_pton AF_INET6 échoue pour IPv4 pure → mac_from_eui64 nil → "unknown"
      mac = get_mac "10.0.0.1"
      assert.equals "unknown", mac

  -- ── mac_from_eui64 : branche inet_pton échoue ───────────────────────────

  describe "mac_from_eui64 inet_pton failure", ->
    it "chaîne avec ':' mais IPv6 invalide → inet_pton retourne 0 → nil", ->
      -- "not:a:valid:v6" passe le filtre find(':') mais inet_pton AF_INET6 retourne 0
      mac = mac_from_eui64 "not:a:valid:v6addr:xyz"
      assert.is_nil mac

    it "chaîne '::-' invalide → nil", ->
      mac = mac_from_eui64 "zz::gg::hh"
      assert.is_nil mac

  -- ── get_mac : chemin post-connect (learner actif) ───────────────────────
  -- On lance un serveur Unix socket en LuaJIT pour simuler le mac_learner.

  describe "get_mac avec learner actif", ->
    SOCK_PATH = "./tmp/test_mac_ipc_query.sock"
    server_pid = nil

    -- Vérifie la compatibilité du layout de struct sockaddr_un.
    -- Si socket.lua a été chargé avant ce spec, sa_family_t = unsigned int (4 bytes)
    -- au lieu de unsigned short (2 bytes), ce qui casse mac_learner_ipc (addr_len hardcodé).
    -- Dans ce cas, on skippe les tests qui nécessitent une vraie connexion AF_UNIX.
    un_family_size = ffi.sizeof(ffi.typeof("struct sockaddr_un")) - 108  -- sun_family offset
    compatible_layout = (un_family_size == 2)

    -- Démarre le serveur LuaJIT en arrière-plan et attend la création du socket.
    -- Retourne le PID du processus background.
    start_server = (response, max_conns) ->
      max_conns = max_conns or 5
      script = "./tmp/mac_server_test.lua"
      fh = io.open script, "w"
      fh\write [=[
local ffi = require "ffi"
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
]=]
      fh\close!
      os.execute "rm -f " .. SOCK_PATH
      pid_file = SOCK_PATH .. ".pid"
      os.execute string.format(
        "luajit %s %s %s %d >/dev/null 2>&1 & echo $! > %s",
        script, string.format("%q", SOCK_PATH), string.format("%q", response), max_conns, pid_file
      )
      -- Attendre que le socket Unix soit créé (os.execute retourne true en LuaJIT)
      for i = 1, 40
        if os.execute("test -S " .. SOCK_PATH)
          os.execute "sleep 1"  -- petit délai supplémentaire pour listen()
          break
        os.execute "sleep 1"
      -- Lire le PID
      fh_pid = io.open pid_file, "r"
      pid = 0
      if fh_pid
        pid = tonumber(fh_pid\read "*l") or 0
        fh_pid\close!
        os.remove pid_file
      pid

    stop_server = (pid) ->
      os.execute "kill #{pid} 2>/dev/null; true"
      os.remove SOCK_PATH

    before_each ->
      -- Recharger mac_learner_ipc avec le bon socket path
      package.loaded["mac_learner_ipc"] = nil
      cfg = package.loaded["config"]
      cfg.MAC_LEARNER_QUERY_SOCK = SOCK_PATH

    after_each ->
      stop_server server_pid if server_pid
      server_pid = nil
      -- Restaurer socket path non-existent pour isoler les autres tests
      cfg = package.loaded["config"]
      cfg.MAC_LEARNER_QUERY_SOCK = "/nonexistent/custos/mac_query.sock"
      package.loaded["mac_learner_ipc"] = nil

    it "learner répond avec un MAC valide → retourne ce MAC", ->
      -- Ce test nécessite que struct sockaddr_un ait sun_family = 2 octets (unsigned short).
      -- Si socket.lua a été chargé avant, sa_family_t = unsigned int (4 octets) → skip.
      pending "struct sockaddr_un incompatible (sa_family_t=uint32 de socket.lua)" unless compatible_layout
      server_pid = start_server "aa:bb:cc:dd:ee:ff", 3
      m = require "mac_learner_ipc"
      result = m.get_mac "10.0.0.1"
      assert.equals "aa:bb:cc:dd:ee:ff", result

    it "learner répond avec MAC invalide + IP non-EUI-64 → \"unknown\"", ->
      pending "struct sockaddr_un incompatible (sa_family_t=uint32 de socket.lua)" unless compatible_layout
      server_pid = start_server "INVALID_RESPONSE", 3
      m = require "mac_learner_ipc"
      result = m.get_mac "10.0.0.1"
      assert.equals "unknown", result

    it "learner répond avec MAC invalide + IP EUI-64 → MAC via fallback", ->
      pending "struct sockaddr_un incompatible (sa_family_t=uint32 de socket.lua)" unless compatible_layout
      server_pid = start_server "INVALID", 3
      m = require "mac_learner_ipc"
      -- fe80::211:22ff:fe33:4455 → MAC 00:11:22:33:44:55
      result = m.get_mac "fe80::211:22ff:fe33:4455"
      assert.equals "00:11:22:33:44:55", result

  -- ── get_mac : n <= 0 (recv retourne 0 ou erreur) ────────────────────────
  -- Serveur ferme connexion sans envoyer de données

  describe "get_mac recv vide (n <= 0)", ->
    SOCK_PATH2 = "./tmp/test_mac_ipc_empty.sock"
    server_pid2 = nil
    un_family_size2 = ffi.sizeof(ffi.typeof("struct sockaddr_un")) - 108
    compatible2 = (un_family_size2 == 2)

    before_each ->
      package.loaded["mac_learner_ipc"] = nil
      cfg = package.loaded["config"]
      cfg.MAC_LEARNER_QUERY_SOCK = SOCK_PATH2

    after_each ->
      os.execute "kill #{server_pid2} 2>/dev/null; true" if server_pid2
      os.remove SOCK_PATH2
      server_pid2 = nil
      cfg = package.loaded["config"]
      cfg.MAC_LEARNER_QUERY_SOCK = "/nonexistent/custos/mac_query.sock"
      package.loaded["mac_learner_ipc"] = nil

    it "learner ferme connexion sans données → \"unknown\"", ->
      pending "struct sockaddr_un incompatible (sa_family_t=uint32 de socket.lua)" unless compatible2
      -- Serveur qui accepte mais ne renvoie rien (n <= 0)
      os.execute "rm -f " .. SOCK_PATH2
      script = "./tmp/mac_server_empty.lua"
      fh_script = io.open script, "w"
      fh_script\write [=[
local ffi = require "ffi"
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
]=]
      fh_script\close!
      cmd = string.format(
        "luajit %s %s 3 >/dev/null 2>&1 & echo $!",
        script, string.format("%q", SOCK_PATH2)
      )
      fh = io.popen cmd
      pid_str = fh\read "*l"
      fh\close!
      server_pid2 = tonumber pid_str
      -- Attendre que le socket Unix soit créé (os.execute retourne true en LuaJIT)
      for i = 1, 20
        if os.execute("test -S " .. SOCK_PATH2)
          os.execute "sleep 1"
          break
        os.execute "sleep 1"
      m = require "mac_learner_ipc"
      result = m.get_mac "10.0.0.1"
      assert.equals "unknown", result

  -- ── get_mac : mock libc — couvre sock<0 et chemin post-connect ───────────
  -- Ces tests remplacent ffi_defs.libc par un proxy Lua permettant de
  -- simuler des erreurs de socket ou des réponses contrôlées.
  -- Ils n'utilisent PAS struct sockaddr_un → pas de conflit de layout.

  describe "get_mac mock libc", ->
    -- Proxy libc : table plate avec des wrappers Lua qui appellent ffi.C.*
    -- directement (sans pré-cache au niveau describe — évite les accès à
    -- ffi.C sous le debug hook de luacov qui peut les désactiver).
    make_mock_libc = ->
      {
        socket:           (a, b, c)    -> ffi.C.socket a, b, c
        close:            (fd)         -> ffi.C.close fd
        connect:          (s, a, l)    -> ffi.C.connect s, a, l
        send:             (s, b, n, f) -> ffi.C.send s, b, n, f
        recv:             (s, b, n, f) -> ffi.C.recv s, b, n, f
        inet_pton:        (af, src, d) -> ffi.C.inet_pton af, src, d
        __errno_location: ()           -> ffi.C.__errno_location!
      }

    orig_ffi_defs = nil
    mock_libc = nil

    before_each ->
      -- Sauvegarder ffi_defs original
      orig_ffi_defs = package.loaded["ffi_defs"]
      -- Créer un nouveau mock libc
      mock_libc = make_mock_libc!
      -- Injecter dans ffi_defs stub
      package.loaded["ffi_defs"] = {
        ffi: ffi,
        libc: mock_libc,
        libnfq: {},
        libnft: {},
      }
      -- Recharger mac_learner_ipc pour qu'il capture le mock libc
      package.loaded["mac_learner_ipc"] = nil
      cfg = package.loaded["config"]
      cfg.MAC_LEARNER_QUERY_SOCK = "/nonexistent/sock"

    after_each ->
      -- Restaurer ffi_defs original
      package.loaded["ffi_defs"] = orig_ffi_defs
      package.loaded["mac_learner_ipc"] = nil
      mock_libc = nil

    it "socket() retourne -1 → log_warn + fallback EUI-64 ou unknown", ->
      -- Couvre la branche 'sock < 0' : log_warn + errno + return fallback
      log_calls = {}
      old_log = package.loaded["log"]
      -- Lazy logging : log_warn reçoit un thunk, on l'appelle pour extraire les fields
      package.loaded["log"] = { log_warn: (thunk) -> log_calls[#log_calls + 1] = thunk! }
      -- Simuler socket() qui échoue : remplacer la fonction dans mock_libc
      mock_libc.socket = -> -1
      m = require "mac_learner_ipc"
      result = m.get_mac "10.0.0.1"
      -- Vérifier que la branche sock<0 a été prise
      assert.equals "unknown", result
      assert.equals 1, #log_calls
      assert.equals "mac_ipc_socket_failed", log_calls[1].action
      package.loaded["log"] = old_log

    it "socket() retourne -1 + IP EUI-64 → fallback EUI-64", ->
      -- Couvre la branche 'sock < 0' avec fallback mac_from_eui64 réussi
      package.loaded["log"] = { log_warn: (thunk) -> nil }
      mock_libc.socket = -> -1
      m = require "mac_learner_ipc"
      -- fe80::211:22ff:fe33:4455 → 00:11:22:33:44:55
      result = m.get_mac "fe80::211:22ff:fe33:4455"
      assert.equals "00:11:22:33:44:55", result

    it "connect réussi + recv MAC valide → retourne MAC", ->
      -- Couvre le chemin post-connect complet (send/recv/parse)
      pcall -> ffi.cdef "int socketpair(int domain, int type, int protocol, int sv[2]);"
      sv = ffi.new "int[2]"
      rc = ffi.C.socketpair 1, 1, 0, sv
      pending "socketpair non disponible" unless rc == 0
      -- Écrire la réponse côté serveur (sv[1]) AVANT que get_mac lise
      mac_resp = "aa:bb:cc:dd:ee:ff"
      ffi.C.send sv[1], mac_resp, #mac_resp, 0
      ffi.C.close sv[1]
      -- Remplacer socket() → fd client déjà connecté
      client_fd = sv[0]
      mock_libc.socket = -> client_fd
      -- Remplacer connect() → succès
      mock_libc.connect = (s, a, l) -> 0
      -- Mocker send() → no-op (sv[1] fermé, évite SIGPIPE)
      mock_libc.send = (s, b, n, f) -> n
      m = require "mac_learner_ipc"
      result = m.get_mac "10.0.0.1"
      assert.equals "aa:bb:cc:dd:ee:ff", result

    it "connect réussi + recv réponse invalide + non-EUI-64 → unknown", ->
      pcall -> ffi.cdef "int socketpair(int domain, int type, int protocol, int sv[2]);"
      sv = ffi.new "int[2]"
      rc = ffi.C.socketpair 1, 1, 0, sv
      pending "socketpair non disponible" unless rc == 0
      resp = "NOT_A_MAC"
      ffi.C.send sv[1], resp, #resp, 0
      ffi.C.close sv[1]
      client_fd = sv[0]
      mock_libc.socket = -> client_fd
      mock_libc.connect = (s, a, l) -> 0
      mock_libc.send = (s, b, n, f) -> n
      m = require "mac_learner_ipc"
      result = m.get_mac "10.0.0.1"
      assert.equals "unknown", result

    it "connect réussi + recv réponse invalide + IP EUI-64 → MAC via EUI-64", ->
      pcall -> ffi.cdef "int socketpair(int domain, int type, int protocol, int sv[2]);"
      sv = ffi.new "int[2]"
      rc = ffi.C.socketpair 1, 1, 0, sv
      pending "socketpair non disponible" unless rc == 0
      resp = "INVALID_MAC"
      ffi.C.send sv[1], resp, #resp, 0
      ffi.C.close sv[1]
      client_fd = sv[0]
      mock_libc.socket = -> client_fd
      mock_libc.connect = (s, a, l) -> 0
      mock_libc.send = (s, b, n, f) -> n
      m = require "mac_learner_ipc"
      -- fe80::211:22ff:fe33:4455 → 00:11:22:33:44:55 via EUI-64 fallback
      result = m.get_mac "fe80::211:22ff:fe33:4455"
      assert.equals "00:11:22:33:44:55", result

    it "connect réussi + recv retourne 0 (connexion fermée) → unknown", ->
      pcall -> ffi.cdef "int socketpair(int domain, int type, int protocol, int sv[2]);"
      sv = ffi.new "int[2]"
      rc = ffi.C.socketpair 1, 1, 0, sv
      pending "socketpair non disponible" unless rc == 0
      -- Fermer le côté serveur sans envoyer → recv retourne 0
      ffi.C.close sv[1]
      client_fd = sv[0]
      mock_libc.socket = -> client_fd
      mock_libc.connect = (s, a, l) -> 0
      mock_libc.send = (s, b, n, f) -> n
      m = require "mac_learner_ipc"
      result = m.get_mac "10.0.0.1"
      assert.equals "unknown", result
