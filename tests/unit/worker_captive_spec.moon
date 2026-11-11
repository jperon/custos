-- tests/unit/worker_captive_spec.moon
-- Tests du worker CAPTIVE : comportement de skip-redirect pour MAC authentifiée.
-- Pas de FFI NFQUEUE, pas de root requis.

bit = require "bit"
sp  = require("ipparse.lib.pack_compat").pack
{ :s2ip } = require "ipparse.l3.ip"
eth_mod = require "ipparse.l2.ethernet"
ip_mod  = require "ipparse.l3.ip"
tcp_mod = require "ipparse.l4.tcp"

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

  -- ── should_throttle_redirect (anti-rafale des redirections) ──────────────────
  -- Une page avec plusieurs ressources bloquées génère un SYN/80 par ressource ;
  -- sans throttling, le navigateur ouvrirait autant de connexions TLS vers le
  -- portail en rafale, au risque de saturer son backlog d'écoute et de faire
  -- échouer une connexion concurrente légitime (ex. POST /login).
  describe "should_throttle_redirect", ->
    captive = require "worker_captive"

    it "première redirection pour une IP : jamais supprimée", ->
      state = {}
      assert.is_false captive.should_throttle_redirect "10.0.0.1", 1000, 5, state

    it "redirection répétée dans la fenêtre : supprimée", ->
      state = {}
      captive.should_throttle_redirect "10.0.0.1", 1000, 5, state
      assert.is_true captive.should_throttle_redirect "10.0.0.1", 1002, 5, state

    it "redirection après expiration de la fenêtre : de nouveau autorisée", ->
      state = {}
      captive.should_throttle_redirect "10.0.0.1", 1000, 5, state
      assert.is_false captive.should_throttle_redirect "10.0.0.1", 1006, 5, state

    it "IPs différentes : discriminées indépendamment", ->
      state = {}
      captive.should_throttle_redirect "10.0.0.1", 1000, 5, state
      assert.is_false captive.should_throttle_redirect "10.0.0.2", 1000, 5, state

  -- ── purge_redirect_rl ──────────────────────────────────────────────────
  -- Sans purge, chaque IP ayant un jour déclenché une redirection reste dans
  -- _redirect_rl indéfiniment (fuite mémoire non bornée, notable en IPv6 où
  -- la rotation d'adresses de confidentialité multiplie les IP par appareil).
  describe "purge_redirect_rl", ->
    captive = require "worker_captive"

    it "supprime les entrées plus vieilles que la fenêtre", ->
      state = { "10.0.0.1": 1000, "10.0.0.2": 1000 }
      captive.purge_redirect_rl 1010, 5, state
      assert.is_nil state["10.0.0.1"]
      assert.is_nil state["10.0.0.2"]

    it "conserve les entrées encore dans la fenêtre", ->
      state = { "10.0.0.1": 1000 }
      captive.purge_redirect_rl 1002, 5, state
      assert.equals 1000, state["10.0.0.1"]

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

  -- ── build_response_frames (forge TCP du portail captif) ─────────────────────
  -- Trois trames : SYN-ACK, données HTTP 302, FIN-ACK. Vérifie octets exacts
  -- (adresses inversées, ports, séquences, flags, payload) et checksums IP/TCP
  -- recalculés indépendamment (RFC 1071 / RFC 793).
  describe "build_response_frames", ->
    captive = require "worker_captive"

    CLIENT_MAC  = "\170\187\204\221\238\255"   -- aa:bb:cc:dd:ee:ff
    BRIDGE_MAC  = "\2\0\0\0\0\1"               -- 02:00:00:00:00:01
    CLIENT_IP   = "\10\0\0\1"                  -- 10.0.0.1
    PORTAL_IP   = "\10\0\0\2"                  -- 10.0.0.2
    CLIENT_PORT = 12345
    CLIENT_SEQ  = 1000
    URL         = "https://10.0.0.2:33443/"
    HTTP_BODY   = "HTTP/1.1 302 Found\r\nLocation: #{URL}\r\n" ..
      "Content-Length: 0\r\nConnection: close\r\n\r\n"

    -- SYN IPv4/TCP sans en-tête Ethernet (payload NFQUEUE).
    build_syn = ->
      ip = sp(">B B H H H B B H", 0x45, 0, 40, 0x1234, 0x4000, 64, 6, 0) ..
        CLIENT_IP .. PORTAL_IP
      tcp = sp(">H H I4 I4 B B H H H", CLIENT_PORT, 80, CLIENT_SEQ, 0,
        0x50, 0x02, 8192, 0, 0)
      ip .. tcp

    ones_sum = (s) ->
      sum = 0
      i = 1
      while i + 1 <= #s
        sum += s\byte(i) * 256 + s\byte(i + 1)
        i += 2
      sum += s\byte(i) * 256 if i == #s
      sum

    fold16 = (sum) ->
      while bit.rshift(sum, 16) != 0
        sum = bit.band(sum, 0xFFFF) + bit.rshift(sum, 16)
      sum

    parse_frame = (frame) ->
      eth, _ = eth_mod.parse frame, 1
      ip, _  = ip_mod.parse frame, eth.data_off
      tcp, _ = tcp_mod.parse frame, ip.data_off
      eth, ip, tcp

    ip_cksum_ok = (frame, ip) ->
      hdr = frame\sub ip.off, ip.off + ip.ihl * 4 - 1
      fold16(ones_sum hdr) == 0xFFFF

    tcp_cksum_ok = (frame, ip, tcp) ->
      tcp_len = ip.total_len - ip.ihl * 4
      seg = frame\sub tcp.off, tcp.off + tcp_len - 1
      src = frame\sub ip.off + 12, ip.off + 15
      dst = frame\sub ip.off + 16, ip.off + 19
      pseudo = src .. dst .. "\0" .. string.char(6) .. sp(">H", tcp_len)
      fold16(ones_sum(pseudo) + ones_sum(seg)) == 0xFFFF

    build = ->
      ip, _ip_off, tcp, _tcp_off = captive.parse_syn build_syn!
      eth = eth_mod.new src: CLIENT_MAC, dst: BRIDGE_MAC, protocol: eth_mod.proto.IP4
      captive.build_response_frames eth, ip, tcp, URL

    it "forge trois trames Ethernet/IPv4/TCP avec adresses inversées", ->
      f1, f2, f3 = build!
      assert.equals "string", type f1
      assert.equals "string", type f2
      assert.equals "string", type f3

      e1, ip1, tcp1 = parse_frame f1
      assert.equals CLIENT_MAC, e1.dst
      assert.equals BRIDGE_MAC, e1.src
      assert.equals eth_mod.proto.IP4, e1.protocol
      assert.equals 4, ip1.version
      assert.equals 64, ip1.ttl
      assert.equals PORTAL_IP, ip1.src
      assert.equals CLIENT_IP, ip1.dst
      assert.equals 80, tcp1.spt
      assert.equals CLIENT_PORT, tcp1.dpt

    it "SYN-ACK : flags SYN+ACK, ack = seq client + 1, pas de charge utile", ->
      f1 = build!
      e1, ip1, tcp1 = parse_frame f1
      assert.equals 0x12, tcp1.flags                  -- SYN + ACK
      assert.equals CLIENT_SEQ + 1, tcp1.ack_n
      assert.equals 65535, tcp1.window
      assert.equals "", f1\sub tcp1.data_off

    it "données : flags PSH+ACK, seq = SYNCK.seq + 1, corps HTTP 302", ->
      f1, f2, _ = build!
      _, _, tcp1 = parse_frame f1
      e2, ip2, tcp2 = parse_frame f2
      assert.equals 0x18, tcp2.flags                  -- PSH + ACK
      assert.equals (tcp1.seq_n + 1) % 0x100000000, tcp2.seq_n
      assert.equals CLIENT_SEQ + 1, tcp2.ack_n
      assert.equals HTTP_BODY, f2\sub tcp2.data_off
      assert.equals 20 + 20 + #HTTP_BODY, ip2.total_len

    it "FIN-ACK : flags FIN+ACK, seq = seq données + longueur du corps", ->
      _, f2, f3 = build!
      _, _, tcp2 = parse_frame f2
      _, _, tcp3 = parse_frame f3
      assert.equals 0x11, tcp3.flags                  -- FIN + ACK
      assert.equals (tcp2.seq_n + #HTTP_BODY) % 0x100000000, tcp3.seq_n
      assert.equals "", f3\sub tcp3.data_off

    it "les checksums IPv4 et TCP des trois trames sont valides", ->
      for frame in *{build!}
        _e, ip, tcp = parse_frame frame
        assert.is_true ip_cksum_ok(frame, ip), "checksum IPv4 invalide"
        assert.is_true tcp_cksum_ok(frame, ip, tcp), "checksum TCP invalide"
