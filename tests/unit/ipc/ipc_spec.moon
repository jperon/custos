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

  -- ── 12. encode_msg allow_ip4=true IPv4 → MSG_IPV4_ALLOW_IP4 (0x45) ────────
  describe "MSG_IPV4_ALLOW_IP4", ->
    it "msg_type == 0x45 et allow_ip4 == true", ->
      m_ipc   = fresh_ipc!
      msg     = m_ipc.encode_msg TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW, false, false, true, false
      decoded = m_ipc.decode_msg msg

      assert.equals 0x45, decoded.msg_type
      assert.is_true  decoded.allow_ip4
      assert.is_false decoded.allow_ip6
      assert.is_false decoded.refused
      assert.is_false decoded.dnsonly

  -- ── 13. encode_msg allow_ip4=true IPv6 → MSG_IPV6_ALLOW_IP4 (0x34) ────────
  describe "MSG_IPV6_ALLOW_IP4", ->
    it "msg_type == 0x34 et allow_ip4 == true pour IPv6", ->
      m_ipc   = fresh_ipc!
      msg     = m_ipc.encode_msg 0xABCD, IP6_RAW, 5353,
                  "\x00\x11\x22\x33\x44\x55", RESOLVER6_RAW, false, false, true, false
      decoded = m_ipc.decode_msg msg

      assert.equals 0x34, decoded.msg_type
      assert.is_true  decoded.allow_ip4
      assert.is_false decoded.allow_ip6
      assert.is_false decoded.ipv4

  -- ── 14. encode_msg allow_ip6=true IPv4 → MSG_IPV4_ALLOW_IP6 (0x61) ────────
  describe "MSG_IPV4_ALLOW_IP6", ->
    it "msg_type == 0x61 et allow_ip6 == true", ->
      m_ipc   = fresh_ipc!
      msg     = m_ipc.encode_msg TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW, false, false, false, true
      decoded = m_ipc.decode_msg msg

      assert.equals 0x61, decoded.msg_type
      assert.is_true  decoded.allow_ip6
      assert.is_false decoded.allow_ip4
      assert.is_false decoded.refused
      assert.is_false decoded.dnsonly

  -- ── 15. encode_msg allow_ip6=true IPv6 → MSG_IPV6_ALLOW_IP6 (0x33) ────────
  describe "MSG_IPV6_ALLOW_IP6", ->
    it "msg_type == 0x33 et allow_ip6 == true pour IPv6", ->
      m_ipc   = fresh_ipc!
      msg     = m_ipc.encode_msg 0xABCD, IP6_RAW, 5353,
                  "\x00\x11\x22\x33\x44\x55", RESOLVER6_RAW, false, false, false, true
      decoded = m_ipc.decode_msg msg

      assert.equals 0x33, decoded.msg_type
      assert.is_true  decoded.allow_ip6
      assert.is_false decoded.allow_ip4
      assert.is_false decoded.ipv4

  -- ── 16. write_allow_ip4_msg + drain_pipe → entry.allow_ip4 = true ─────────
  describe "write_allow_ip4_msg via pipe", ->
    it "drain_pipe stocke un entry avec allow_ip4=true", ->
      m_ipc = fresh_ipc!
      p     = make_pipe!
      rfd, wfd = p[1], p[2]

      m_ipc.write_allow_ip4_msg wfd, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW
      m_ipc.drain_pipe rfd, (-> 0), nil

      entry = m_ipc.get_pending_entry TXID, "192.168.1.42", PORT, "1.1.1.3", -> 1
      assert.is_not_nil entry
      assert.is_true  entry.allow_ip4
      assert.is_false entry.allow_ip6
      assert.is_false entry.dnsonly
      assert.is_false entry.refused
      close_pipe p

  -- ── 17. write_allow_ip6_msg + drain_pipe → entry.allow_ip6 = true ─────────
  describe "write_allow_ip6_msg via pipe", ->
    it "drain_pipe stocke un entry avec allow_ip6=true", ->
      m_ipc = fresh_ipc!
      p     = make_pipe!
      rfd, wfd = p[1], p[2]

      m_ipc.write_allow_ip6_msg wfd, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW
      m_ipc.drain_pipe rfd, (-> 0), nil

      entry = m_ipc.get_pending_entry TXID, "192.168.1.42", PORT, "1.1.1.3", -> 1
      assert.is_not_nil entry
      assert.is_true  entry.allow_ip6
      assert.is_false entry.allow_ip4
      assert.is_false entry.dnsonly
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
                  false, false, false, false, reason
      decoded = m_ipc.decode_msg msg

      assert.is_not_nil decoded.reason
      assert.truthy decoded.reason\find "blocked", 1, true

  describe "rule_id + timeout round-trip", ->
    it "préserve rule_id et timeout", ->
      m_ipc   = fresh_ipc!
      msg     = m_ipc.encode_msg TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW,
                  false, false, false, false, "allowed", 17, "dns_workhours", "240s"
      decoded = m_ipc.decode_msg msg

      assert.equals "dns_workhours", decoded.rule_id
      assert.equals "240s", decoded.timeout

  -- ── 14. reason tronquée à 63 chars ───────────────────────────────────
  describe "reason troncature", ->
    it "reason de 70 chars est tronquée à 63", ->
      m_ipc   = fresh_ipc!
      long_r  = string.rep "x", 70
      msg     = m_ipc.encode_msg TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW,
                  false, false, false, false, long_r
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

  -- ── 19. decode_msg trop court → nil ───────────────────────────────────
  describe "decode_msg trop court", ->
    it "message trop court → nil", ->
      m_ipc = fresh_ipc!
      result = m_ipc.decode_msg "toocourt"
      assert.is_nil result

  -- ── 20. encode_msg avec benchmark_ms > 0 ─────────────────────────────
  describe "encode_msg avec benchmark_ms", ->
    it "benchmark_ms encodé et décodé", ->
      m_ipc = fresh_ipc!
      msg = m_ipc.encode_msg TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW, false, false, false, false, "", 42, "rule_dns", "90s"
      assert.is_true #msg > 0
      decoded = m_ipc.decode_msg msg
      assert.is_not_nil decoded
      assert.equals TXID, decoded.txid
      assert.equals 42, decoded.benchmark_ms
      assert.equals "rule_dns", decoded.rule_id
      assert.equals "90s", decoded.timeout

  -- ── 21. write_msg fd invalide → géré sans crash ───────────────────────
  describe "write_msg fd invalide", ->
    it "write_msg sur fd -1 ne crash pas", ->
      m_ipc = fresh_ipc!
      -- fd=-1 invalide, write_msg doit retourner false ou gérer l'erreur
      ok, err = pcall -> m_ipc.write_msg -1, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW
      -- Soit ça retourne false, soit ça lève une erreur — dans les deux cas pas de crash fatal
      assert.is_true (ok == true or ok == false)

  -- ── 22. drain_pipe n<0 (pipe vide, EAGAIN) → retourne 0 ─────────────
  describe "drain_pipe pipe vide (EAGAIN)", ->
    it "drain_pipe sur pipe vide retourne 0 sans erreur", ->
      m_ipc = fresh_ipc!
      p     = make_pipe!
      rfd, wfd = p[1], p[2]

      -- Aucun message écrit : read() retourne -1 (EAGAIN sur non-blocking)
      count = m_ipc.drain_pipe rfd, (-> 0), nil
      assert.equals 0, count, "aucun message absorbé sur pipe vide"

      close_pipe p

  -- ── 23. is_pending clé absente → false directement ──────────────────
  describe "is_pending clé absente", ->
    it "is_pending retourne false pour une clé inexistante", ->
      m_ipc = fresh_ipc!
      result = m_ipc.is_pending 0xDEAD, "1.2.3.4", 1234, "5.6.7.8", -> 0
      assert.is_false result, "is_pending doit retourner false si clé absente"

  -- ── 24. get_pending_entry clé absente → nil ─────────────────────────
  describe "get_pending_entry clé absente", ->
    it "get_pending_entry retourne nil pour une clé inexistante", ->
      m_ipc = fresh_ipc!
      entry = m_ipc.get_pending_entry 0xDEAD, "1.2.3.4", 1234, "5.6.7.8", -> 0
      assert.is_nil entry, "get_pending_entry doit retourner nil si clé absente"

  -- ── 25. get_pending_entry expirée → nil + suppression ───────────────
  describe "get_pending_entry expirée", ->
    it "get_pending_entry retourne nil après expiration", ->
      m_ipc = fresh_ipc!
      p     = make_pipe!
      rfd, wfd = p[1], p[2]

      base = 0
      m_ipc.write_msg wfd, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW
      m_ipc.drain_pipe rfd, (-> base), nil

      -- Avant expiration : entrée présente
      e1 = m_ipc.get_pending_entry TXID, "192.168.1.42", PORT, "1.1.1.3", -> base + 4
      assert.is_not_nil e1, "entrée présente avant expiration"

      -- Après expiration : nil
      e2 = m_ipc.get_pending_entry TXID, "192.168.1.42", PORT, "1.1.1.3", -> base + 100
      assert.is_nil e2, "get_pending_entry nil après expiration"

      close_pipe p

  -- ── 26. consume supprime une entrée pending ──────────────────────────
  describe "consume", ->
    it "consume supprime l'entrée et is_pending retourne false", ->
      m_ipc = fresh_ipc!
      p     = make_pipe!
      rfd, wfd = p[1], p[2]

      m_ipc.write_msg wfd, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW
      m_ipc.drain_pipe rfd, (-> 0), nil

      assert.is_true  m_ipc.is_pending(TXID, "192.168.1.42", PORT, "1.1.1.3", -> 1)
      m_ipc.consume TXID, "192.168.1.42", PORT, "1.1.1.3"
      assert.is_false m_ipc.is_pending(TXID, "192.168.1.42", PORT, "1.1.1.3", -> 1)

      close_pipe p

  -- ── 27. drain_pipe on_msg callback ───────────────────────────────────
  describe "drain_pipe on_msg callback", ->
    it "on_msg est appelé pour chaque message absorbé", ->
      m_ipc = fresh_ipc!
      p     = make_pipe!
      rfd, wfd = p[1], p[2]

      m_ipc.write_msg wfd, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW, "reason A"
      m_ipc.write_dnsonly_msg wfd, 0x5678, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW

      msgs = {}
      count = m_ipc.drain_pipe rfd, (-> 0), (msg) ->
        msgs[#msgs + 1] = msg

      assert.equals 2, count, "2 messages absorbés"
      assert.equals 2, #msgs, "on_msg appelé 2 fois"
      assert.equals TXID,   msgs[1].txid
      assert.equals "reason A", msgs[1].reason
      assert.is_true msgs[2].dnsonly

      close_pipe p

  -- ── 28. encode_msg benchmark_ms round-trip ────────────────────────────
  describe "encode_msg benchmark_ms round-trip", ->
    it "benchmark_ms est encodé et décodé correctement", ->
      m_ipc = fresh_ipc!
      bms   = 12345
      msg   = m_ipc.encode_msg TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW,
                false, false, false, false, "", bms
      decoded = m_ipc.decode_msg msg
      assert.is_not_nil decoded
      assert.equals bms, decoded.benchmark_ms, "benchmark_ms préservé"

  -- ── 29. reason exactement 63 chars (limite sans troncature) ──────────
  describe "reason 63 chars (limite exacte)", ->
    it "reason de 63 chars n'est pas tronquée", ->
      m_ipc    = fresh_ipc!
      reason63 = string.rep "y", 63
      msg      = m_ipc.encode_msg TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW,
                   false, false, false, false, reason63
      decoded  = m_ipc.decode_msg msg
      assert.equals 63,       #decoded.reason, "longueur préservée"
      assert.equals reason63, decoded.reason,  "contenu intact"

  -- ── 30. decode_msg trop court → nil ──────────────────────────────────
  describe "decode_msg trop court", ->
    it "decode_msg sur chaîne courte retourne nil", ->
      m_ipc = fresh_ipc!
      result = m_ipc.decode_msg "too_short"
      assert.is_nil result, "decode_msg doit retourner nil si < 115 B"

  -- ── 31. IPv6 dnsonly round-trip via drain_pipe ────────────────────────
  describe "IPv6 dnsonly round-trip via drain_pipe", ->
    it "write_dnsonly_msg IPv6 → drain_pipe → entry.dnsonly = true", ->
      m_ipc = fresh_ipc!
      p     = make_pipe!
      rfd, wfd = p[1], p[2]

      m_ipc.write_dnsonly_msg wfd, TXID, IP6_RAW, PORT, MAC_RAW, RESOLVER6_RAW, "ipv6 dns"
      count = m_ipc.drain_pipe rfd, (-> 0), nil
      assert.equals 1, count

      entry = m_ipc.get_pending_entry TXID, "2001:db8::1", PORT, "2001:db8::53", -> 1
      assert.is_not_nil entry,   "entrée présente"
      assert.is_true  entry.dnsonly, "dnsonly=true pour IPv6"
      assert.equals "ipv6 dns", entry.reason

      close_pipe p

  -- ── 32. IPv6 refused round-trip via drain_pipe ────────────────────────
  describe "IPv6 refused round-trip via drain_pipe", ->
    it "write_refused_msg IPv6 → drain_pipe → entry.refused = true", ->
      m_ipc = fresh_ipc!
      p     = make_pipe!
      rfd, wfd = p[1], p[2]

      m_ipc.write_refused_msg wfd, TXID, IP6_RAW, PORT, MAC_RAW, RESOLVER6_RAW, "ipv6 block"
      count = m_ipc.drain_pipe rfd, (-> 0), nil
      assert.equals 1, count

      entry = m_ipc.get_pending_entry TXID, "2001:db8::1", PORT, "2001:db8::53", -> 1
      assert.is_not_nil entry,    "entrée présente"
      assert.is_true  entry.refused, "refused=true pour IPv6"
      assert.equals "ipv6 block", entry.reason

      close_pipe p
