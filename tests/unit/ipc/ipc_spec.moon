-- tests/unit/ipc/ipc_spec.moon
-- Spec Busted pour lua/ipc.lua.
--
-- Conventions :
--   • chaque groupe qui doit un état propre recharge ipc via dofile.
--   • le module ipc.lua maintient une table `pending` module-level ;
--     recharger le module la remet à zéro.
--   • les tests pipe utilisent pipe2(O_NONBLOCK) et ferment les fd après usage.

ffi = require "ffi"

-- ── cdef POSIX additionnels ───────────────────────────────────────────────
-- busted_setup.lua déclare timespec_t / inet_ntop / inet_pton / nanosleep.
-- On déclare ici pipe2/fcntl/close/read/write — idempotent via pcall.
pcall ffi.cdef, [[
  int pipe2(int pipefd[2], int flags);
  int fcntl(int fd, int cmd, ...);
  int close(int fd);
  ssize_t read(int fd, void *buf, size_t count);
  ssize_t write(int fd, const void *buf, size_t count);
  int* __errno_location();
]]

-- ── Constantes locales ────────────────────────────────────────────────────
O_NONBLOCK    = 2048

IP4_RAW       = "\xC0\xA8\x01\x2A"   -- 192.168.1.42
RESOLVER4_RAW = "\x01\x01\x01\x03"   -- 1.1.1.3
MAC_RAW       = "\xAA\xBB\xCC\xDD\xEE\xFF"
TXID          = 0x1234
PORT          = 54321

IP6_RAW       = "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
RESOLVER6_RAW = "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x53"

-- ── Helper : crée un pipe non-bloquant, retourne {rfd, wfd} ──────────────
make_pipe = ->
  pipefd = ffi.new "int[2]"
  r = ffi.C.pipe2 pipefd, O_NONBLOCK
  assert r == 0, "pipe2 a échoué"
  { pipefd[0], pipefd[1] }

close_pipe = (p) ->
  ffi.C.close p[1]
  ffi.C.close p[2]

-- ── Helper : instancie un module ipc.lua frais ────────────────────────────
fresh_ipc = ->
  package.loaded["ipc"] = nil
  dofile "lua/ipc.lua"

-- ═════════════════════════════════════════════════════════════════════════
describe "ipc", ->

  -- ── 1. encode/decode IPv4 round-trip ─────────────────────────────────
  describe "encode/decode IPv4 round-trip", ->
    it "round-trip complet avec MAC", ->
      m_ipc   = fresh_ipc!
      msg     = m_ipc.encode_msg TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW
      decoded = m_ipc.decode_msg msg

      assert.equals TXID,             decoded.txid
      assert.equals PORT,             decoded.src_port
      assert.equals "192.168.1.42",   decoded.ip_str
      assert.equals "1.1.1.3",        decoded.resolver_ip_str
      assert.equals 0x41,             decoded.msg_type   -- MSG_IPV4
      assert.equals "aa:bb:cc:dd:ee:ff", decoded.mac_str
      assert.is_true  decoded.ipv4
      assert.is_false decoded.refused
      assert.is_false decoded.dnsonly

  -- ── 2. encode/decode IPv4 sans MAC (nil) ─────────────────────────────
  describe "encode/decode IPv4 sans MAC", ->
    it "mac nil → 00:00:00:00:00:00", ->
      m_ipc   = fresh_ipc!
      msg     = m_ipc.encode_msg 0x1234, "\xC0\xA8\x01\x2A", 54321, nil, "\x01\x01\x01\x01"
      decoded = m_ipc.decode_msg msg

      assert.equals "1.1.1.1",           decoded.resolver_ip_str
      assert.equals "00:00:00:00:00:00", decoded.mac_str

  -- ── 3. encode/decode IPv6 round-trip ─────────────────────────────────
  describe "encode/decode IPv6 round-trip", ->
    it "round-trip avec adresses IPv6", ->
      m_ipc   = fresh_ipc!
      msg     = m_ipc.encode_msg 0xABCD, IP6_RAW, 5353,
                  "\x00\x11\x22\x33\x44\x55", RESOLVER6_RAW
      decoded = m_ipc.decode_msg msg

      assert.equals "2001:db8::1",  decoded.ip_str
      assert.equals "2001:db8::53", decoded.resolver_ip_str
      assert.equals 0x36,           decoded.msg_type   -- MSG_IPV6
      assert.is_false decoded.ipv4
      assert.is_false decoded.refused
      assert.is_false decoded.dnsonly

  -- ── 4. make_key — unicité ─────────────────────────────────────────────
  describe "make_key", ->
    it "des paramètres différents donnent des clés différentes", ->
      m_ipc = fresh_ipc!
      k1 = m_ipc.make_key 0x1234, "192.168.1.1", 53, "1.1.1.1"
      k2 = m_ipc.make_key 0x1234, "192.168.1.2", 53, "1.1.1.1"
      k3 = m_ipc.make_key 0x5678, "192.168.1.1", 53, "1.1.1.1"
      k4 = m_ipc.make_key 0x1234, "192.168.1.1", 53, "1.1.1.3"

      assert.not_equals k1, k2
      assert.not_equals k1, k3
      assert.not_equals k1, k4

  -- ── 5. drain_pipe — lit un message sans overflow ──────────────────────
  describe "drain_pipe", ->
    it "écrit write_msg, drain_pipe absorbe le message et is_pending est vrai", ->
      m_ipc = fresh_ipc!
      p     = make_pipe!
      rfd, wfd = p[1], p[2]

      ok = m_ipc.write_msg wfd, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW
      assert.is_true ok

      now_t   = 1000
      count   = m_ipc.drain_pipe rfd, (-> now_t), nil
      assert.equals 1, count

      pending = m_ipc.is_pending TXID, "192.168.1.42", PORT, "1.1.1.3", -> now_t + 1
      assert.is_true pending

      close_pipe p

  -- ── 6. token expiré est rejeté (purge paresseuse) ────────────────────
  describe "expiration de token", ->
    it "valide à t+4, expiré à t+6 (TTL=5)", ->
      m_ipc = fresh_ipc!
      p     = make_pipe!
      rfd, wfd = p[1], p[2]

      base = 0
      m_ipc.write_msg wfd, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW
      m_ipc.drain_pipe rfd, (-> base), nil

      assert.is_true  m_ipc.is_pending(TXID, "192.168.1.42", PORT, "1.1.1.3", -> base + 4)
      assert.is_false m_ipc.is_pending(TXID, "192.168.1.42", PORT, "1.1.1.3", -> base + 6)

      close_pipe p

  -- ── 7. encode_msg refused=true IPv4 → MSG_IPV4_REFUSED (0x52) ────────
  describe "MSG_IPV4_REFUSED", ->
    it "msg_type == 0x52 et refused == true", ->
      m_ipc   = fresh_ipc!
      msg     = m_ipc.encode_msg TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW, true, false
      decoded = m_ipc.decode_msg msg

      assert.equals 0x52, decoded.msg_type
      assert.is_true  decoded.refused
      assert.is_false decoded.dnsonly

  -- ── 8. decode MSG_IPV6_REFUSED (0x72) → refused=true, ipv4=false ─────
  describe "MSG_IPV6_REFUSED", ->
    it "refused=true et ipv4=false pour une adresse IPv6", ->
      m_ipc   = fresh_ipc!
      msg     = m_ipc.encode_msg 0xABCD, IP6_RAW, 5353,
                  "\x00\x11\x22\x33\x44\x55", RESOLVER6_RAW, true, false
      decoded = m_ipc.decode_msg msg

      assert.equals 0x72, decoded.msg_type
      assert.is_true  decoded.refused
      assert.is_false decoded.ipv4

  -- ── 9. encode_msg dnsonly=true IPv4 → MSG_IPV4_DNSONLY (0x44) ────────
  describe "MSG_IPV4_DNSONLY", ->
    it "msg_type == 0x44 et dnsonly == true", ->
      m_ipc   = fresh_ipc!
      msg     = m_ipc.encode_msg TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW, false, true
      decoded = m_ipc.decode_msg msg

      assert.equals 0x44, decoded.msg_type
      assert.is_true  decoded.dnsonly
      assert.is_false decoded.refused

  -- ── 10. encode_msg dnsonly=true IPv6 → MSG_IPV6_DNSONLY (0x64) ───────
  describe "MSG_IPV6_DNSONLY", ->
    it "msg_type == 0x64 et dnsonly == true pour IPv6", ->
      m_ipc   = fresh_ipc!
      msg     = m_ipc.encode_msg 0xABCD, IP6_RAW, 5353,
                  "\x00\x11\x22\x33\x44\x55", RESOLVER6_RAW, false, true
      decoded = m_ipc.decode_msg msg

      assert.equals 0x64, decoded.msg_type
      assert.is_true  decoded.dnsonly
      assert.is_false decoded.refused

  -- ── 11. write_dnsonly_msg + drain_pipe → entry.dnsonly = true ─────────
  describe "write_dnsonly_msg via pipe", ->
    it "drain_pipe stocke un entry avec dnsonly=true", ->
      m_ipc = fresh_ipc!
      p     = make_pipe!
      rfd, wfd = p[1], p[2]

      m_ipc.write_dnsonly_msg wfd, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW
      m_ipc.drain_pipe rfd, (-> 0), nil

      entry = m_ipc.get_pending_entry TXID, "192.168.1.42", PORT, "1.1.1.3", -> 1
      assert.is_not_nil entry
      assert.is_true  entry.dnsonly
      assert.is_false entry.refused

      close_pipe p

  -- ── 12. write_refused_msg + drain_pipe → entry.refused = true ─────────
  describe "write_refused_msg via pipe", ->
    it "drain_pipe stocke un entry avec refused=true", ->
      m_ipc = fresh_ipc!
      p     = make_pipe!
      rfd, wfd = p[1], p[2]

      m_ipc.write_refused_msg wfd, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW
      m_ipc.drain_pipe rfd, (-> 0), nil

      entry = m_ipc.get_pending_entry TXID, "192.168.1.42", PORT, "1.1.1.3", -> 1
      assert.is_not_nil entry
      assert.is_true  entry.refused
      assert.is_false entry.dnsonly

      close_pipe p

  -- ── 13. reason round-trip via encode/decode ───────────────────────────
  describe "reason round-trip", ->
    it "reason est préservée après encode + decode", ->
      m_ipc   = fresh_ipc!
      reason  = "blocked by policy"
      msg     = m_ipc.encode_msg TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW,
                  false, false, reason
      decoded = m_ipc.decode_msg msg

      assert.is_not_nil decoded.reason
      assert.truthy decoded.reason\find "blocked", 1, true

  -- ── 14. reason tronquée à 63 chars ───────────────────────────────────
  describe "reason troncature", ->
    it "reason de 70 chars est tronquée à 63", ->
      m_ipc   = fresh_ipc!
      long_r  = string.rep "x", 70
      msg     = m_ipc.encode_msg TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW,
                  false, false, long_r
      decoded = m_ipc.decode_msg msg

      assert.equals 63, #decoded.reason

  -- ── 15. write_refused_msg avec reason → entry.reason préservé ─────────
  describe "write_refused_msg + reason", ->
    it "entry.reason est préservée après drain_pipe", ->
      m_ipc  = fresh_ipc!
      p      = make_pipe!
      rfd, wfd = p[1], p[2]

      m_ipc.write_refused_msg wfd, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW, "policy block"
      m_ipc.drain_pipe rfd, (-> 0), nil

      entry = m_ipc.get_pending_entry TXID, "192.168.1.42", PORT, "1.1.1.3", -> 1
      assert.is_not_nil entry
      assert.equals "policy block", entry.reason

      close_pipe p

  -- ── 16. reason absente → entry.reason vide ou nil ─────────────────────
  describe "reason absente", ->
    it "entry.reason est vide quand aucune reason n'est fournie", ->
      m_ipc = fresh_ipc!
      p     = make_pipe!
      rfd, wfd = p[1], p[2]

      m_ipc.write_msg wfd, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW
      m_ipc.drain_pipe rfd, (-> 0), nil

      entry = m_ipc.get_pending_entry TXID, "192.168.1.42", PORT, "1.1.1.3", -> 1
      assert.is_not_nil entry
      -- reason doit être nil ou la chaîne vide
      assert.truthy entry.reason == nil or entry.reason == ""

      close_pipe p

  -- ── 17. write_msg avec reason → entry.reason préservé ─────────────────
  describe "write_msg + reason", ->
    it "entry.reason est préservée pour un message normal", ->
      m_ipc  = fresh_ipc!
      p      = make_pipe!
      rfd, wfd = p[1], p[2]

      m_ipc.write_msg wfd, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW, "custom reason"
      m_ipc.drain_pipe rfd, (-> 0), nil

      entry = m_ipc.get_pending_entry TXID, "192.168.1.42", PORT, "1.1.1.3", -> 1
      assert.is_not_nil entry
      assert.equals "custom reason", entry.reason

      close_pipe p

  -- ── 18. write_dnsonly_msg avec reason → entry.reason préservé ─────────
  describe "write_dnsonly_msg + reason", ->
    it "entry.reason est préservée pour un message dnsonly", ->
      m_ipc  = fresh_ipc!
      p      = make_pipe!
      rfd, wfd = p[1], p[2]

      m_ipc.write_dnsonly_msg wfd, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW, "dnsonly reason"
      m_ipc.drain_pipe rfd, (-> 0), nil

      entry = m_ipc.get_pending_entry TXID, "192.168.1.42", PORT, "1.1.1.3", -> 1
      assert.is_not_nil entry
      assert.equals "dnsonly reason", entry.reason

      close_pipe p
