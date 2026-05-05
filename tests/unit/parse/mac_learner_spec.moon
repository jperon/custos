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
