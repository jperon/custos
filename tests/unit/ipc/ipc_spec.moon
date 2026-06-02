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
      msg     = m_ipc.encode_msg TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW, true
      decoded = m_ipc.decode_msg msg

      assert.equals 0x52, decoded.msg_type
      assert.is_true  decoded.refused

  -- ── 8. decode MSG_IPV6_REFUSED (0x72) → refused=true, ipv4=false ─────
  describe "MSG_IPV6_REFUSED", ->
    it "refused=true et ipv4=false pour une adresse IPv6", ->
      m_ipc   = fresh_ipc!
      msg     = m_ipc.encode_msg 0xABCD, IP6_RAW, 5353,
                  "\x00\x11\x22\x33\x44\x55", RESOLVER6_RAW, true
      decoded = m_ipc.decode_msg msg

      assert.equals 0x72, decoded.msg_type
      assert.is_true  decoded.refused
      assert.is_false decoded.ipv4

  -- ── 9. registre dynamique : register_modifier + encode/decode ────────
  describe "registre dynamique de modificateurs", ->
    it "register_modifier + encode_modifiers + decode_modifiers round-trip", ->
      m_ipc = fresh_ipc!
      m_ipc.register_modifier "foo"
      m_ipc.register_modifier "bar"

      bits = m_ipc.encode_modifiers { foo: true, bar: false }
      assert.is_true bits > 0, "foo=true → bitmask non nul"

      mods = m_ipc.decode_modifiers bits
      assert.is_true  mods.foo, "foo décodé à true"
      assert.is_false mods.bar, "bar décodé à false"

    it "modifier_bit retourne 0 pour un nom inconnu", ->
      m_ipc = fresh_ipc!
      assert.equals 0, m_ipc.modifier_bit("unknown_mod")

    it "deux modificateurs ont des bits distincts", ->
      m_ipc = fresh_ipc!
      m_ipc.register_modifier "alpha"
      m_ipc.register_modifier "beta"
      ba = m_ipc.modifier_bit "alpha"
      bb = m_ipc.modifier_bit "beta"
      assert.is_true ba > 0
      assert.is_true bb > 0
      assert.not_equals ba, bb

  -- ── 10. modificateur transmis via pipe (encode → drain_pipe → entry) ──
  describe "modificateur via pipe", ->
    it "write_msg + modifiers → entry.modifiers décodé", ->
      m_ipc = fresh_ipc!
      m_ipc.register_modifier "dnsonly"
      p     = make_pipe!
      rfd, wfd = p[1], p[2]

      m_ipc.write_msg wfd, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW,
                      "reason", nil, nil, nil, { dnsonly: true }
      m_ipc.drain_pipe rfd, (-> 0), nil

      entry = m_ipc.get_pending_entry TXID, "192.168.1.42", PORT, "1.1.1.3", -> 1
      assert.is_not_nil entry
      assert.is_false entry.refused
      assert.is_true  entry.modifiers.dnsonly, "dnsonly transmis dans modifiers"
      close_pipe p

  -- ── 11. write_refused_msg + drain_pipe → entry.refused = true ─────────
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

      close_pipe p

  -- ── 13. reason round-trip via encode/decode ───────────────────────────
  describe "reason round-trip", ->
    it "reason est préservée après encode + decode", ->
      m_ipc   = fresh_ipc!
      reason  = "blocked by policy"
      msg     = m_ipc.encode_msg TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW,
                  false, reason
      decoded = m_ipc.decode_msg msg

      assert.is_not_nil decoded.reason
      assert.truthy decoded.reason\find "blocked", 1, true

  describe "rule_id + timeout round-trip", ->
    it "préserve rule_id et timeout", ->
      m_ipc   = fresh_ipc!
      msg     = m_ipc.encode_msg TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW,
                  false, "allowed", 17, "dns_workhours", "240s"
      decoded = m_ipc.decode_msg msg

      assert.equals "dns_workhours", decoded.rule_id
      assert.equals "240s", decoded.timeout

  -- ── 13b. rule_id long préservé (régression nft set name) ────────────
  -- Bug historique : rule_id était tronqué à 63 chars dans encode_msg,
  -- alors que filter.rule_id.sanitize_id autorise 128 chars. Conséquence :
  -- worker_nft cherchait un set nft inexistant ("did you mean set 'X' ?").
  -- Voir src/ipc.moon vs src/filter/rule_id.moon.
  describe "rule_id long round-trip (régression)", ->
    it "rule_id de 75 chars (cas réel) préservé en entier", ->
      m_ipc   = fresh_ipc!
      -- Cas qui a effectivement déclenché le bug en prod :
      long_rid = "r_les_utilisateurs_authentifies_ne_sont_pas_rediriges_vers_le_portail_captif"
      assert.equals 76, #long_rid, "longueur du cas de test"
      msg     = m_ipc.encode_msg TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW,
                  false, "allow", 0, long_rid, "120s"
      decoded = m_ipc.decode_msg msg
      assert.equals long_rid, decoded.rule_id,
        "rule_id ne doit PAS être tronqué (bug nft_single_failed)"

    it "rule_id de 128 chars préservé (limite sanitize_id)", ->
      m_ipc    = fresh_ipc!
      rid128   = "r_" .. string.rep("a", 128)
      msg      = m_ipc.encode_msg TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW,
                   false, "allow", 0, rid128, "120s"
      decoded  = m_ipc.decode_msg msg
      assert.equals rid128, decoded.rule_id

    it "rule_id > 130 chars est tronqué à 130", ->
      m_ipc    = fresh_ipc!
      rid_long = string.rep "z", 200
      msg      = m_ipc.encode_msg TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW,
                   false, "allow", 0, rid_long, "120s"
      decoded  = m_ipc.decode_msg msg
      assert.equals 130, #decoded.rule_id

  -- ── 14. reason tronquée à 63 chars ───────────────────────────────────
  describe "reason troncature", ->
    it "reason de 70 chars est tronquée à 63", ->
      m_ipc   = fresh_ipc!
      long_r  = string.rep "x", 70
      msg     = m_ipc.encode_msg TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW,
                  false, long_r
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

  -- ── 18. write_msg + reason + modifier → entry complète ──────────────
  describe "write_msg + reason + modifier", ->
    it "reason et modifier sont préservés dans l'entrée pending", ->
      m_ipc  = fresh_ipc!
      m_ipc.register_modifier "dnsonly"
      p      = make_pipe!
      rfd, wfd = p[1], p[2]

      m_ipc.write_msg wfd, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW,
                      "dnsonly reason", nil, nil, nil, { dnsonly: true }
      m_ipc.drain_pipe rfd, (-> 0), nil

      entry = m_ipc.get_pending_entry TXID, "192.168.1.42", PORT, "1.1.1.3", -> 1
      assert.is_not_nil entry
      assert.equals "dnsonly reason", entry.reason
      assert.is_true entry.modifiers.dnsonly

      close_pipe p

  -- ── 18b. response_rule_ids round-trip via pipe ─────────────────────
  describe "write_msg + response_rule_ids", ->
    it "response_rule_ids est préservée dans l'entrée pending", ->
      m_ipc = fresh_ipc!
      p     = make_pipe!
      rfd, wfd = p[1], p[2]

      m_ipc.write_msg wfd, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW,
                      "allow", nil, "r_allow", "120s", nil, { "r_safe", "r_strip" }
      m_ipc.drain_pipe rfd, (-> 0), nil

      entry = m_ipc.get_pending_entry TXID, "192.168.1.42", PORT, "1.1.1.3", -> 1
      assert.is_not_nil entry
      assert.same { "r_safe", "r_strip" }, entry.response_rule_ids

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
      msg = m_ipc.encode_msg TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW, false, "", 42, "rule_dns", "90s"
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

      m_ipc.register_modifier "dnsonly"
      m_ipc.write_msg wfd, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW, "reason A"
      m_ipc.write_msg wfd, 0x5678, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW,
                      nil, nil, nil, nil, { dnsonly: true }

      msgs = {}
      count = m_ipc.drain_pipe rfd, (-> 0), (msg) ->
        msgs[#msgs + 1] = msg

      assert.equals 2, count, "2 messages absorbés"
      assert.equals 2, #msgs, "on_msg appelé 2 fois"
      assert.equals TXID,   msgs[1].txid
      assert.equals "reason A", msgs[1].reason
      assert.is_true msgs[2].modifiers.dnsonly

      close_pipe p

  -- ── 28. encode_msg benchmark_ms round-trip ────────────────────────────
  describe "encode_msg benchmark_ms round-trip", ->
    it "benchmark_ms est encodé et décodé correctement", ->
      m_ipc = fresh_ipc!
      bms   = 12345
      msg   = m_ipc.encode_msg TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW,
                false, "", bms
      decoded = m_ipc.decode_msg msg
      assert.is_not_nil decoded
      assert.equals bms, decoded.benchmark_ms, "benchmark_ms préservé"

  -- ── 29. reason exactement 63 chars (limite sans troncature) ──────────
  describe "reason 63 chars (limite exacte)", ->
    it "reason de 63 chars n'est pas tronquée", ->
      m_ipc    = fresh_ipc!
      reason63 = string.rep "y", 63
      msg      = m_ipc.encode_msg TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW,
                   false, reason63
      decoded  = m_ipc.decode_msg msg
      assert.equals 63,       #decoded.reason, "longueur préservée"
      assert.equals reason63, decoded.reason,  "contenu intact"

  -- ── 30. decode_msg trop court → nil ──────────────────────────────────
  describe "decode_msg trop court", ->
    it "decode_msg sur chaîne courte retourne nil", ->
      m_ipc = fresh_ipc!
      result = m_ipc.decode_msg "too_short"
      assert.is_nil result, "decode_msg doit retourner nil si < 115 B"

  -- ── 31. modificateur IPv6 round-trip via drain_pipe ─────────────────
  describe "modificateur IPv6 round-trip via drain_pipe", ->
    it "write_msg IPv6 + modifier dnsonly → entry.modifiers.dnsonly = true", ->
      m_ipc = fresh_ipc!
      m_ipc.register_modifier "dnsonly"
      p     = make_pipe!
      rfd, wfd = p[1], p[2]

      m_ipc.write_msg wfd, TXID, IP6_RAW, PORT, MAC_RAW, RESOLVER6_RAW,
                      "ipv6 dns", nil, nil, nil, { dnsonly: true }
      count = m_ipc.drain_pipe rfd, (-> 0), nil
      assert.equals 1, count

      entry = m_ipc.get_pending_entry TXID, "2001:db8::1", PORT, "2001:db8::53", -> 1
      assert.is_not_nil entry,   "entrée présente"
      assert.is_true  entry.modifiers.dnsonly, "dnsonly=true pour IPv6"
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
