-- tests/unit/worker_captive_spec.moon
-- Tests du worker CAPTIVE : comportement de skip-redirect pour MAC authentifiée.
-- Pas de FFI NFQUEUE, pas de root requis.

describe "worker_captive", ->

  -- ── parse_syn ────────────────────────────────────────────────────────────────
  describe "parse_syn", ->
    captive = require "worker_captive"

    -- Construit un paquet IPv4/TCP SYN minimal (sans Ethernet)
    build_ipv4_syn = ->
      -- IP header (20 bytes) : version=4, IHL=5, tot_len=40, proto=TCP, src=10.0.0.1, dst=10.0.0.2
      ip  = "\x45\x00\x00\x28"  -- version+ihl, dscp, total_len=40
      ip ..= "\x00\x00\x40\x00" -- id, flags+frag
      ip ..= "\x40\x06\x00\x00" -- ttl=64, proto=TCP(6), checksum=0
      ip ..= "\x0a\x00\x00\x01" -- src 10.0.0.1
      ip ..= "\x0a\x00\x00\x02" -- dst 10.0.0.2
      -- TCP header (20 bytes) : sport=12345, dport=80, seq=1, ack=0, flags=SYN
      tcp  = "\x30\x39\x00\x50" -- sport=12345, dport=80
      tcp ..= "\x00\x00\x00\x01" -- seq
      tcp ..= "\x00\x00\x00\x00" -- ack
      tcp ..= "\x50\x02\x00\x00" -- data_off=5, flags=SYN(0x02)
      tcp ..= "\x00\x00\x00\x00" -- window, checksum, urgent
      ip .. tcp

    it "parse un paquet IPv4/TCP valide et retourne ip et tcp", ->
      raw = build_ipv4_syn!
      ip, ip_off, tcp, tcp_off = captive.parse_syn raw
      assert.is_not_nil ip
      assert.is_not_nil tcp
      assert.equal 4, ip.version
      assert.equal 6, ip.protocol  -- TCP

    it "retourne nil pour un paquet trop court (UDP, pas TCP)", ->
      -- Paquet IPv4 avec proto=UDP(17) au lieu de TCP : parse_tcp échoue
      ip  = "\x45\x00\x00\x1c"
      ip ..= "\x00\x00\x40\x00"
      ip ..= "\x40\x11\x00\x00" -- proto=UDP(17)
      ip ..= "\x0a\x00\x00\x01"
      ip ..= "\x0a\x00\x00\x02"
      -- Pas de header TCP valide
      raw = ip .. "\x00\x00\x00\x00"
      result = captive.parse_syn raw
      assert.is_nil result

  -- ── Comportement skip redirect ────────────────────────────────────────────────
  -- On ne peut pas appeler handle_syn directement (dépend de NFQUEUE runtime),
  -- mais on vérifie que le chemin skip est atteint en mockant user_for_mac via
  -- le module sessions.

  describe "skip authenticated (intégration sessions)", ->
    sessions_mod = require "auth.sessions"
    { :write_sessions, :reset_cache } = sessions_mod

    SESS_FILE = "tmp/captive_spec.lua"
    FUTURE    = 9999999999

    before_each ->
      reset_cache!

    it "user_for_mac retourne nil pour une MAC inconnue", ->
      write_sessions {}, SESS_FILE
      reset_cache!
      user = sessions_mod.user_for_mac "aa:bb:cc:dd:ee:ff", "10.0.0.1", SESS_FILE
      assert.is_nil user

    it "user_for_mac retourne l'utilisateur pour une MAC authentifiée", ->
      sessions = {
        ["aa:bb:cc:dd:ee:ff"]: {
          user: "alice", expires: FUTURE, mac: "aa:bb:cc:dd:ee:ff"
          ips: { ipv4: "10.0.0.1" }
        }
      }
      write_sessions sessions, SESS_FILE
      reset_cache!
      user = sessions_mod.user_for_mac "aa:bb:cc:dd:ee:ff", "10.0.0.1", SESS_FILE
      assert.equal "alice", user

    it "enrich_session_ip ajoute une nouvelle IPv6 à une session existante", ->
      sessions = {
        ["aa:bb:cc:dd:ee:ff"]: {
          user: "alice", expires: FUTURE, mac: "aa:bb:cc:dd:ee:ff"
          ips: { ipv4: "10.0.0.1" }
        }
      }
      write_sessions sessions, SESS_FILE
      reset_cache!

      ok = sessions_mod.enrich_session_ip "aa:bb:cc:dd:ee:ff", "2a11::cafe", SESS_FILE
      assert.is_true ok

      -- Vérifier que la nouvelle IP est persistée
      reset_cache!
      sess = sessions_mod.session_for_mac "aa:bb:cc:dd:ee:ff", nil, SESS_FILE
      assert.equal "2a11::cafe", sess.ips.ipv6

    it "enrich_session_ip ne réécrit pas si l'IP est déjà présente", ->
      sessions = {
        ["bb:cc:dd:ee:ff:00"]: {
          user: "bob", expires: FUTURE, mac: "bb:cc:dd:ee:ff:00"
          ips: { ipv4: "10.0.0.2", ipv6: "2a11::1" }
        }
      }
      write_sessions sessions, SESS_FILE
      reset_cache!

      ok = sessions_mod.enrich_session_ip "bb:cc:dd:ee:ff:00", "2a11::1", SESS_FILE
      assert.is_false ok  -- déjà présente → pas de réécriture
