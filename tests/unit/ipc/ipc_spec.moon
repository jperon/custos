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

-- ── Helper : force `ipc.pending_max` pendant l'exécution de `fn` ─────────
-- `ipc.lua` lit `ipc.pending_max` au chargement (via `ipc_cfg`) : la config
-- doit donc être installée AVANT `fresh_ipc!`, puis restaurée.
with_pending_max = (max, fn) ->
  cfg   = package.loaded["config"]
  saved = cfg.ipc
  cfg.ipc = { pending_ttl: 5, pending_max: max }
  ok, err = pcall fn
  cfg.ipc = saved
  error err unless ok

-- ── Helper : installe `ipc` ET `runtime` (profil lowmem) avant `fresh_ipc!` ──
-- `ipc.lua` résout la borne `pending` au chargement (lowmem.resolve_pending_max).
with_ipc_profile = (max, runtime, fn) ->
  cfg = package.loaded["config"]
  saved_ipc, saved_runtime = cfg.ipc, cfg.runtime
  cfg.ipc = { pending_ttl: 5, pending_max: max }
  cfg.runtime = runtime
  ok, err = pcall fn
  cfg.ipc, cfg.runtime = saved_ipc, saved_runtime
  error err unless ok

-- ── Helper : message décodé minimal pour `set_pending` ───────────────────
make_pending_msg = (txid, port, rule_id) ->
  {
    txid: txid
    ip_str: "192.168.1.42"
    src_port: port
    resolver_ip_str: "1.1.1.3"
    refused: false
    modifiers: {}
    reason: "ok"
    benchmark_ms: nil
    question_proc_ms: nil
    rule_id: rule_id or ""
    timeout: "2m"
    response_rule_ids: {}
  }

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

  -- ── purge_pending : purge active des entrées jamais relues ───────────
  -- Sans purge_pending, une entrée `pending` dont personne n'appelle jamais
  -- is_pending/get_pending_entry (paquet perdu, upstream muet, client qui
  -- abandonne) reste en mémoire indéfiniment (fuite non bornée dans le
  -- worker le plus sollicité).
  describe "purge_pending", ->
    it "supprime une entrée expirée jamais relue", ->
      m_ipc = fresh_ipc!
      p     = make_pipe!
      rfd, wfd = p[1], p[2]

      base = 0
      m_ipc.write_msg wfd, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW
      m_ipc.drain_pipe rfd, (-> base), nil

      -- Jamais lu via is_pending/get_pending_entry : sans purge_pending,
      -- l'entrée resterait en mémoire pour toujours.
      m_ipc.purge_pending -> base + 6

      -- Réécrit une entrée pour le même txid/ip/port/resolver : si l'ancienne
      -- entrée n'a pas été purgée, is_pending pourrait renvoyer un état
      -- incohérent issu de l'entrée fantôme (même clé).
      assert.is_false m_ipc.is_pending(TXID, "192.168.1.42", PORT, "1.1.1.3", -> base + 6)

      close_pipe p

    it "conserve une entrée non expirée", ->
      m_ipc = fresh_ipc!
      p     = make_pipe!
      rfd, wfd = p[1], p[2]

      base = 0
      m_ipc.write_msg wfd, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW
      m_ipc.drain_pipe rfd, (-> base), nil

      m_ipc.purge_pending -> base + 2
      assert.is_true m_ipc.is_pending(TXID, "192.168.1.42", PORT, "1.1.1.3", -> base + 2)

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

  -- ── 20b. question_proc_ms round-trip + rétrocompat (champ absent) ────
  describe "encode_msg avec question_proc_ms", ->
    it "question_proc_ms encodé et décodé", ->
      m_ipc = fresh_ipc!
      msg = m_ipc.encode_msg TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW,
        false, "", 1000, "rule_dns", "90s", nil, nil, 7
      decoded = m_ipc.decode_msg msg
      assert.is_not_nil decoded
      assert.equals 1000, decoded.benchmark_ms
      assert.equals 7, decoded.question_proc_ms

    it "message sans champ question_proc_ms → nil (rétrocompat)", ->
      m_ipc = fresh_ipc!
      -- message 13 champs (sans question_proc_ms)
      msg = m_ipc.encode_msg TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW,
        false, "", 1000, "rule_dns", "90s"
      -- retire le dernier champ (question_proc) ajouté par encode_msg
      trimmed = msg\gsub("|0\n$", "\n")
      decoded = m_ipc.decode_msg trimmed
      assert.is_not_nil decoded
      assert.is_nil decoded.question_proc_ms

  -- ── 23. fan-out : write_msg vers plusieurs pipes (multi-worker réponses) ──
  describe "write_msg fan-out (plusieurs workers réponses)", ->
    it "écrit la même transaction dans TOUS les pipes", ->
      m_ipc = fresh_ipc!
      p1    = make_pipe!
      p2    = make_pipe!
      now_t = 5000

      ok = m_ipc.write_msg { p1[2], p2[2] }, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW
      assert.is_true ok

      -- Chaque worker réponses reçoit sa copie : la transaction doit être
      -- appariable dans les deux (l'appariement ne dépend pas de l'affinité).
      assert.equals 1, (m_ipc.drain_pipe p1[1], (-> now_t), nil)
      assert.is_true m_ipc.is_pending TXID, "192.168.1.42", PORT, "1.1.1.3", -> now_t + 1
      assert.equals 1, (m_ipc.drain_pipe p2[1], (-> now_t), nil)
      assert.is_true m_ipc.is_pending TXID, "192.168.1.42", PORT, "1.1.1.3", -> now_t + 1

      close_pipe p1
      close_pipe p2

    -- Un seul destinataire en échec permanent ne doit plus faire jeter la
    -- question : c'est le correctif du blocage définitif multi-worker
    -- (docs/agents/perf.md §12). La question reste acceptée dès qu'un tube l'a
    -- reçue ; seul l'échec de TOUS les destinataires est un échec.
    it "renvoie true quand au moins un destinataire a reçu la ligne", ->
      m_ipc = fresh_ipc!
      p     = make_pipe!

      ok = m_ipc.write_msg { p[2], -1 }, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW
      assert.is_true ok
      -- Le worker qui a reçu la copie peut apparier la transaction.
      assert.equals 1, (m_ipc.drain_pipe p[1], (-> 5000), nil)
      assert.is_true m_ipc.is_pending TXID, "192.168.1.42", PORT, "1.1.1.3", -> 5001

      close_pipe p

    it "renvoie false quand AUCUN destinataire n'a reçu la ligne", ->
      m_ipc = fresh_ipc!

      ok = m_ipc.write_msg { -1, -1 }, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW
      assert.is_false ok

  -- ── 24. fan-out : destinataire durablement plein (EAGAIN) ───────────────
  -- Défaut observé en pré-prod : un worker réponses dont la file NFQUEUE ne
  -- reçoit aucun paquet ne drainait jamais son tube. Le tube (64 Kio) se
  -- remplissait, `write_with_retry` payait alors 5 × 20 ms de nanosleep PAR
  -- QUESTION vers ce destinataire, puis rendait false → worker_questions
  -- renvoyait NF_DROP → plus aucune question, plus aucune réponse : blocage
  -- définitif jusqu'au redémarrage. Correctif : un destinataire saturé ne coûte
  -- plus qu'UNE écriture non bloquante par message (aucun sommeil) et la
  -- question est livrée dès qu'un destinataire l'a reçue.
  describe "write_msg fan-out : destinataire durablement plein (EAGAIN)", ->
    saved_defs = nil
    saved_log  = nil
    sleeps     = 0
    logs       = nil
    eagain     = true
    eagain_fds = nil

    before_each ->
      saved_defs = package.loaded["ffi_defs"]
      saved_log  = package.loaded["log"]
      sleeps     = 0
      logs       = {}
      eagain     = true
      eagain_fds = {}

    after_each ->
      package.loaded["ffi_defs"] = saved_defs
      package.loaded["log"]      = saved_log
      package.loaded["ipc"]      = nil

    -- Les stubs doivent précéder le chargement d'ipc.lua : `libc` et `log` y
    -- sont capturés au require. `write` renvoie EAGAIN pour les fd listés dans
    -- `eagain_fds` et délègue au vrai C sinon ; `nanosleep` est compté.
    stub_env = ->
      errno_box = ffi.new "int[1]"
      libc = setmetatable {
        write: (fd, msg, len) ->
          if eagain and eagain_fds[fd]
            errno_box[0] = 11   -- EAGAIN
            return -1
          ffi.C.write fd, msg, len
        __errno_location: -> errno_box
        nanosleep: (req, rem) ->
          sleeps += 1
          0
      }, { __index: ffi.C }
      package.loaded["ffi_defs"] = { :ffi, :libc }
      capture = (level) -> (thunk) ->
        fields = thunk!
        logs[#logs + 1] = { :level, :fields } if fields
      package.loaded["log"] = {
        log_warn:  capture "warn"
        log_info:  capture "info"
        log_error: capture "error"
        log_debug: capture "debug"
        log_allow: capture "allow"
        log_block: capture "block"
        log_trace: capture "trace"
        now: -> os.time!
        get_log_level_num: -> 0
        level_enabled: -> true
        set_action_prefix: -> nil
      }

    with_logs = (action) ->
      [l for l in *logs when l.fields.action == action]

    it "ne dort qu'au premier échec : aucun nanosleep par question ensuite", ->
      good = make_pipe!
      sat  = make_pipe!
      eagain_fds = { [sat[2]]: true }
      stub_env!
      m_ipc = fresh_ipc!

      -- 1er message : retry complet vers le destinataire plein (5 sommeils).
      assert.is_true m_ipc.write_msg { sat[2], good[2] }, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW
      assert.equals 5, sleeps

      -- Messages suivants : une seule écriture non bloquante, sans sommeil.
      for i = 1, 4
        assert.is_true m_ipc.write_msg { sat[2], good[2] }, TXID + i, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW
      assert.equals 5, sleeps, "aucun nanosleep par question sur un tube saturé"

      -- Le destinataire sain a bien reçu TOUS les messages.
      assert.equals 5, (m_ipc.drain_pipe good[1], (-> 5000), nil)

      -- Un seul WARN de saturation, porté par le destinataire fautif.
      saturated = with_logs "ipc_write_saturated"
      assert.equals 1, #saturated
      assert.equals sat[2], saturated[1].fields.ipc_fd

      close_pipe good
      close_pipe sat

    it "efface l'état saturé dès qu'une écriture réussit", ->
      good = make_pipe!
      sat  = make_pipe!
      eagain_fds = { [sat[2]]: true }
      stub_env!
      m_ipc = fresh_ipc!

      assert.is_true m_ipc.write_msg { sat[2], good[2] }, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW
      assert.equals 5, sleeps

      -- Le tube s'est drainé : la prochaine écriture passe → état effacé.
      eagain = false
      assert.is_true m_ipc.write_msg { sat[2], good[2] }, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW
      assert.equals 1, #with_logs "ipc_write_resumed"
      assert.equals 5, sleeps
      -- Le destinataire naguère saturé a bien reçu ce message.
      assert.equals 1, (m_ipc.drain_pipe sat[1], (-> 5000), nil)

      -- Re-saturation : le retry complet est de nouveau payé (5 sommeils).
      eagain = true
      assert.is_true m_ipc.write_msg { sat[2], good[2] }, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW
      assert.equals 10, sleeps

      close_pipe good
      close_pipe sat

    it "renvoie false si TOUS les destinataires sont pleins", ->
      sat1 = make_pipe!
      sat2 = make_pipe!
      eagain_fds = { [sat1[2]]: true, [sat2[2]]: true }
      stub_env!
      m_ipc = fresh_ipc!

      -- Deux destinataires saturés : la question n'atteint personne.
      assert.is_false m_ipc.write_msg { sat1[2], sat2[2] }, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW
      assert.equals 10, sleeps, "un retry complet par destinataire, puis état saturé"

      close_pipe sat1
      close_pipe sat2

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

  -- ── 33. Réutilisation de clé `pending` : retransmission ou divergence ──
  -- Une question REFUSÉE est bien acheminée : worker_questions l'écrit en
  -- `write_refused_msg` puis renvoie NF_ACCEPT (src/worker_questions.moon:450
  -- et 471) pour laisser la réponse du résolveur revenir ; `set_pending` est
  -- appelé pour TOUT message drainé (src/ipc.moon:390). Une collision avec
  -- verdicts différents est donc un cas atteignable, pas hypothétique.
  --
  -- Politique : cas identique (retransmission UDP) inchangé — first-wins, seul
  -- `expire` est rafraîchi. Divergence → verdict le plus restrictif
  -- (fail-closed) : si l'une des deux questions est refusée, l'entrée conservée
  -- est celle de la question refusée ; deux questions autorisées par des règles
  -- différentes ne permettent pas de prouver qu'un choix n'élargit pas l'accès
  -- (cf. src/worker_responses.moon:599-638), donc l'entrée est marquée refusée.
  describe "réutilisation de clé pending (fail-closed sur divergence)", ->
    it "Q1 autorisée + Q2 refusée → l'entrée conservée est refusée", ->
      m_ipc = fresh_ipc!
      p     = make_pipe!
      rfd, wfd = p[1], p[2]

      -- Q1 autorisée (règle r_allowed).
      ok1 = m_ipc.write_msg wfd, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW,
                          "allowed", nil, "r_allowed"
      assert.is_true ok1
      -- Q2 refusée (règle r_denied), même clé txid+client+port+résolveur.
      ok2 = m_ipc.write_refused_msg wfd, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW,
                                "blocked", nil, "r_denied"
      assert.is_true ok2

      count = m_ipc.drain_pipe rfd, (-> 0), nil
      assert.equals 2, count

      entry = m_ipc.get_pending_entry TXID, "192.168.1.42", PORT, "1.1.1.3", -> 1
      assert.is_not_nil entry
      -- Avant correctif (first-wins), l'entrée restait autorisée : la réponse
      -- à Q2 (refusée) aurait été relayée avec refused=false de Q1 →
      -- contournement du filtre.
      assert.is_true entry.refused, "verdict le plus restrictif : refusé"
      assert.equals "r_denied", entry.rule_id
      assert.equals "blocked",  entry.reason

      close_pipe p

    it "Q1 refusée + Q2 autorisée → l'entrée reste refusée", ->
      m_ipc = fresh_ipc!
      p     = make_pipe!
      rfd, wfd = p[1], p[2]

      m_ipc.write_refused_msg wfd, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW,
                              "blocked", nil, "r_refused"
      m_ipc.write_msg wfd, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW,
                      "allowed", nil, "r_allowed"
      m_ipc.drain_pipe rfd, (-> 0), nil

      entry = m_ipc.get_pending_entry TXID, "192.168.1.42", PORT, "1.1.1.3", -> 1
      assert.is_not_nil entry
      assert.is_true entry.refused
      assert.equals "r_refused", entry.rule_id
      assert.equals "blocked",   entry.reason

      close_pipe p

    it "Q1 et Q2 autorisées par des règles différentes → entrée refusée", ->
      m_ipc = fresh_ipc!
      p     = make_pipe!
      rfd, wfd = p[1], p[2]

      m_ipc.write_msg wfd, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW,
                      "allowed", nil, "r_allow_a"
      m_ipc.write_msg wfd, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW,
                      "allowed", nil, "r_allow_b"
      m_ipc.drain_pipe rfd, (-> 0), nil

      entry = m_ipc.get_pending_entry TXID, "192.168.1.42", PORT, "1.1.1.3", -> 1
      assert.is_not_nil entry
      -- Aucune des deux règles ne peut être prouvée non élargissante pour la
      -- réponse de l'autre (hooks on_response, injection nft) → fail-closed.
      assert.is_true entry.refused
      assert.equals "ipc_pending_conflict", entry.reason

      close_pipe p

    it "une retransmission identique conserve l'entrée et rafraîchit expire", ->
      m_ipc = fresh_ipc!
      p     = make_pipe!
      rfd, wfd = p[1], p[2]

      base = 1000
      m_ipc.write_refused_msg wfd, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW,
                              "blocked", nil, "r_refused"
      m_ipc.drain_pipe rfd, (-> base), nil

      -- Retransmission 3 s plus tard : même question, même verdict.
      m_ipc.write_refused_msg wfd, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW,
                              "blocked", nil, "r_refused"
      m_ipc.drain_pipe rfd, (-> base + 3), nil

      -- L'entrée doit rester valide jusqu'à base+3+5 (expire rafraîchi), et
      -- pas expirer à base+5 comme sans rafraîchissement.
      entry = m_ipc.get_pending_entry TXID, "192.168.1.42", PORT, "1.1.1.3", -> base + 6
      assert.is_not_nil entry, "expire rafraîchi par la retransmission"
      assert.is_true entry.refused
      assert.equals "r_refused", entry.rule_id
      assert.equals "blocked",   entry.reason

      close_pipe p

    it "la retransmission conserve le jalon benchmark de la question d'origine", ->
      m_ipc = fresh_ipc!
      p     = make_pipe!
      rfd, wfd = p[1], p[2]

      m_ipc.write_msg wfd, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW,
                      "ok", 5000, "r_ok", nil, nil, nil, 7
      m_ipc.drain_pipe rfd, (-> 0), nil
      -- Retransmission tardive : jalon plus récent, même question.
      m_ipc.write_msg wfd, TXID, IP4_RAW, PORT, MAC_RAW, RESOLVER4_RAW,
                      "ok", 5900, "r_ok", nil, nil, nil, 9
      m_ipc.drain_pipe rfd, (-> 0), nil

      entry = m_ipc.get_pending_entry TXID, "192.168.1.42", PORT, "1.1.1.3", -> 1
      assert.is_not_nil entry
      assert.equals 5000, entry.benchmark_ms,
        "benchmark_ms = entrée de la première question (base de q_to_response_ms)"
      assert.equals 7, entry.question_proc_ms

      close_pipe p

  -- ── 34. Borne de taille de la table `pending` (ipc.pending_max) ────────
  -- La table `pending` n'avait aucune borne : sous une rafale de questions
  -- sans réponse (résolveur muet, flood client) elle grossissait sans limite
  -- dans CHAQUE worker réponses (fan-out `write_with_retry_all`), donc N fois.
  describe "borne de la table pending (ipc.pending_max)", ->
    it "borne la taille sous 3× la limite et compte les évictions", ->
      with_pending_max 50, ->
        m_ipc  = fresh_ipc!
        now_fn = -> 1000
        for i = 1, 150
          m_ipc.set_pending make_pending_msg(i, 10000 + i), now_fn
        stats = m_ipc.pending_stats!
        assert.equals 50,  stats.size
        assert.equals 100, stats.evicted

    it "évince les plus anciennes et conserve les récentes", ->
      with_pending_max 50, ->
        m_ipc  = fresh_ipc!
        now_fn = -> 1000
        for i = 1, 60
          m_ipc.set_pending make_pending_msg(i, 10000 + i), now_fn
        for i = 1, 10
          assert.is_nil m_ipc.get_pending_entry(i, "192.168.1.42", 10000 + i, "1.1.1.3", now_fn)
        for i = 11, 60
          assert.is_not_nil m_ipc.get_pending_entry(i, "192.168.1.42", 10000 + i, "1.1.1.3", now_fn)

    it "l'appariement des entrées récentes reste intact", ->
      with_pending_max 50, ->
        m_ipc  = fresh_ipc!
        now_fn = -> 1000
        for i = 1, 60
          m_ipc.set_pending make_pending_msg(i, 10000 + i, "r_#{i}"), now_fn
        entry = m_ipc.get_pending_entry 60, "192.168.1.42", 10060, "1.1.1.3", now_fn
        assert.is_not_nil entry
        assert.equals "r_60", entry.rule_id
        assert.equals "ok",   entry.reason

    it "purge par âge inchangée et décrémente la taille", ->
      with_pending_max 50, ->
        m_ipc  = fresh_ipc!
        now_fn = -> 1000
        for i = 1, 10
          m_ipc.set_pending make_pending_msg(i, 10000 + i), now_fn
        m_ipc.purge_pending -> 1002
        assert.equals 10, m_ipc.pending_stats!.size
        assert.equals 0,  m_ipc.pending_stats!.evicted
        m_ipc.purge_pending -> 1006
        assert.equals 0, m_ipc.pending_stats!.size

    it "une entrée expirée lue est retirée de la taille", ->
      with_pending_max 50, ->
        m_ipc  = fresh_ipc!
        m_ipc.set_pending make_pending_msg(1, 10001), -> 1000
        assert.equals 1, m_ipc.pending_stats!.size
        assert.is_false m_ipc.is_pending(1, "192.168.1.42", 10001, "1.1.1.3", -> 1006)
        assert.equals 0, m_ipc.pending_stats!.size

    it "taille mémoire d'une entrée mesurée avec collectgarbage", ->
      m_ipc  = fresh_ipc!
      now_fn = -> 1000
      n      = 1000
      collectgarbage "collect"
      before = collectgarbage "count"
      for i = 1, n
        m_ipc.set_pending make_pending_msg(i, 10000 + i), now_fn
      collectgarbage "collect"
      after  = collectgarbage "count"
      per_entry = (after - before) * 1024 / n
      -- Ordre de grandeur : quelques centaines d'octets (entrée + nœud de
      -- liste + clé). Les bornes larges évitent la fragilité entre versions.
      assert.is_true per_entry > 64,   "entrée non triviale (#{per_entry} o)"
      assert.is_true per_entry < 4096, "entrée < 4 Ko (#{per_entry} o)"

  -- ── 35. Défaut de `ipc.pending_max` selon le profil (lowmem) ───────────
  -- Recommandation de la campagne d-tune (docs/agents/perf.md §15.5) :
  -- 20 000 par défaut, 5 000 en mode RAM faible. Une valeur explicite de
  -- configuration prime toujours (0 = auto, comme `nfqueue.rcvbuf`).
  describe "défaut de pending_max selon le profil", ->
    it "hors RAM faible : 20 000", ->
      with_ipc_profile nil, { lowmem: false }, ->
        m_ipc = fresh_ipc!
        assert.equals 20000, m_ipc.pending_stats!.pending_max

    it "RAM faible : 5 000", ->
      with_ipc_profile nil, { lowmem: true }, ->
        m_ipc = fresh_ipc!
        assert.equals 5000, m_ipc.pending_stats!.pending_max

    it "valeur explicite : elle prime en RAM faible", ->
      with_ipc_profile 12000, { lowmem: true }, ->
        m_ipc = fresh_ipc!
        assert.equals 12000, m_ipc.pending_stats!.pending_max

    it "valeur explicite : elle prime hors RAM faible", ->
      with_ipc_profile 8000, { lowmem: false }, ->
        m_ipc = fresh_ipc!
        assert.equals 8000, m_ipc.pending_stats!.pending_max
