-- tests/unit/mac_learner_core_spec.moon
-- Couverture du cœur du mac_learner resté hors des specs dédiées (probe,
-- VLAN, strip) : apprentissage (process_learn/learn_mac), expiration des
-- probes, traitement des requêtes socket (start_query) et boucle run().
--
-- Le module est rechargé avec des stubs locaux (auth.sessions, mac_prober,
-- ffi_defs pour le test de run) restaurés en fin de fichier. Les sockets des
-- tests unitaires sont de vrais socketpair AF_UNIX (aucun accès root).

ffi = require "ffi"
pcall require, "lib.socket"
{ :libc } = require "ffi_defs"
pcall -> ffi.cdef "int socketpair(int domain, int type, int protocol, int sv[2]);"

AF_UNIX = 1
SOCK_STREAM = 1
POLLIN = 1

mk_pair = ->
  sv = ffi.new "int[2]"
  assert.equals 0, libc.socketpair AF_UNIX, SOCK_STREAM, 0, sv
  sv[0], sv[1]

read_n = (fd, n) ->
  buf = ffi.new "char[?]", n
  got = libc.recv fd, buf, n, 0
  return nil if got < 0
  ffi.string buf, got

-- Encode une IPv4 en ip16 (4 octets + 12 zéros) et une IPv6 brute.
ip4_16 = (a, b, c, d) -> string.char(a, b, c, d) .. string.rep "\0", 12
ip6_16 = (s) ->
  { :s2ip } = require "ipparse.l3.ip"
  s2ip s

mac6 = (s) ->
  out = {}
  for h in s\gmatch "%x%x"
    out[#out + 1] = string.char tonumber(h, 16)
  table.concat out

learn_msg = (ip16, mac_str) -> ip16 .. mac6 mac_str

STUB_KEYS = { "mac_learner", "auth.sessions", "mac_prober", "ffi_defs" }
saved = {}
enrich_calls = 0
mp_stub = nil
w = nil

save_all = -> saved[k] = package.loaded[k] for k in *STUB_KEYS
restore_all = ->
  for k in *STUB_KEYS
    package.loaded[k] = saved[k]

install_stubs = ->
  package.loaded["auth.sessions"] = {
    enrich_session_ip: (mac, ip, path) ->
      enrich_calls += 1
      true
  }
  mp_stub = {
    get_ms: -> now_ms
    send_probe: (ctx, ip) -> true
    init: (ifname) -> nil
  }
  package.loaded["mac_prober"] = mp_stub

load_learner = ->
  package.loaded["mac_learner"] = nil
  require "mac_learner"

now_ms = 0

-- Envoie une requête et lit la réponse attendue (start_query est synchrone).
ask = (req, n=64) ->
  client_fd, peer = mk_pair!
  libc.send peer, req, #req, 0
  w.start_query client_fd
  resp = read_n peer, n
  libc.close peer
  resp

describe "mac_learner cœur", ->
  lazy_setup ->
    save_all!
    install_stubs!
    w = load_learner!
  lazy_teardown ->
    restore_all!

  before_each ->
    enrich_calls = 0
    now_ms = 0
    -- Vide l'état inter-tests sans réassigner les tables (capturées par le
    -- module) : apprendre une IP de test unique suffit pour mac_table, mais
    -- pending_queries doit être purgé explicitement.
    for ip in pairs w.pending_queries
      w.pending_queries[ip] = nil
    mp_stub.get_ms = -> now_ms
    mp_stub.send_probe = (ctx, ip) -> true

  describe "process_learn", ->
    it "apprend une IPv4 (16 octets ip16 + mac6)", ->
      w.process_learn learn_msg (ip4_16 10, 0, 0, 21), "02:00:00:00:00:21"
      assert.equals "02:00:00:00:00:21\n", ask "10.0.0.21\n"
      assert.equals 1, enrich_calls

    it "apprend une IPv6", ->
      w.process_learn learn_msg (ip6_16 "2001:db8::21"), "02:00:00:00:00:22"
      assert.equals "02:00:00:00:00:22\n", ask "2001:db8::21\n"

    it "ignore un message trop court", ->
      w.process_learn "\1\2\3"
      assert.equals "unknown\n", ask "0.0.0.1\n"

    it "ignore une MAC nulle", ->
      w.process_learn learn_msg (ip4_16 10, 0, 0, 22), "00:00:00:00:00:00"
      assert.equals "unknown\n", ask "10.0.0.22\n"

  describe "learn_mac et clients en attente", ->
    it "réveille les clients en attente et ferme leurs fd", ->
      w.pending_queries["10.0.0.30"] = { { 77, 1000 } }
      -- fd 77 est bidon : send/close échouent silencieusement, l'important est
      -- que la file soit vidée et l'apprentissage effectué.
      w.learn_mac "10.0.0.30", "02:00:00:00:00:30"
      assert.is_nil w.pending_queries["10.0.0.30"]
      assert.equals "02:00:00:00:00:30\n", ask "10.0.0.30\n"

    it "n'enrichit la session que si la MAC change", ->
      w.learn_mac "10.0.0.31", "02:00:00:00:00:31"
      assert.equals 1, enrich_calls
      w.learn_mac "10.0.0.31", "02:00:00:00:00:31"
      assert.equals 1, enrich_calls
      w.learn_mac "10.0.0.31", "02:00:00:00:00:99"
      assert.equals 2, enrich_calls

  describe "start_query", ->
    it "répond la MAC connue", ->
      w.learn_mac "10.0.0.40", "02:00:00:00:00:40"
      assert.equals "02:00:00:00:00:40\n", ask "10.0.0.40\n"

    it "purge une entrée expirée puis répond unknown", ->
      w.learn_mac "10.0.0.41", "02:00:00:00:00:41"
      real = os.time
      os.time = -> real! + 10000
      resp = ask "10.0.0.41\n"
      os.time = real
      assert.equals "unknown\n", resp

    it "répond unknown pour une IP inconnue sans prober", ->
      assert.equals "unknown\n", ask "10.0.0.42\n"

    it "répond unknown si le cache négatif est actif", ->
      -- Alimente le cache négatif du module via un échec de sonde.
      client_fd, peer = mk_pair!
      w.probe_request w.pending_queries, w.negative_cache, {}, client_fd, "10.0.0.43",
        (-> 0), (-> false)
      read_n peer, 8
      libc.close peer
      resp = ask "10.0.0.43\n"
      assert.equals "unknown\n", resp

    it "requête VLAN connue puis inconnue", ->
      w.process_vlan_learn (ip4_16 10, 0, 0, 44) .. "\0\100"
      assert.equals "100\n", ask "vlan:10.0.0.44\n"
      assert.equals "unknown\n", ask "vlan:10.0.0.45\n"

    it "requête strip connue puis inconnue", ->
      codec = require "strip_codec"
      w.process_strip_learn codec.encode "strip.example", 28
      assert.equals "28\n", ask "strip:STRIP.example.\n"
      assert.equals "unknown\n", ask "strip:absent.example\n"

    it "requête vide ou client fermé → unknown/fermeture sans erreur", ->
      assert.equals "unknown\n", ask "\n"
      client_fd, peer = mk_pair!
      libc.close client_fd
      w.start_query client_fd   -- fd fermé : recv échoue, fermeture best-effort
      libc.close peer

  describe "expire_pending", ->
    it "répond unknown aux clients expirés et pose le cache négatif", ->
      client_fd, peer = mk_pair!
      now_ms = 1000
      w.pending_queries["10.0.0.50"] = { { client_fd, 500 } }
      now_ms = 2000
      w.expire_pending!
      assert.equals "unknown\n", read_n peer, 8
      assert.is_nil w.pending_queries["10.0.0.50"]
      libc.close peer

    it "conserve les clients non expirés", ->
      client_fd, peer = mk_pair!
      now_ms = 1000
      w.pending_queries["10.0.0.51"] = { { client_fd, 5000 } }
      now_ms = 2000
      w.expire_pending!
      assert.equals 1, #w.pending_queries["10.0.0.51"]
      libc.close client_fd
      libc.close peer

    it "mélange expirés/non expirés dans une même file", ->
      fd1, p1 = mk_pair!
      fd2, p2 = mk_pair!
      now_ms = 1000
      w.pending_queries["10.0.0.52"] = { { fd1, 500 }, { fd2, 5000 } }
      now_ms = 2000
      w.expire_pending!
      assert.equals "unknown\n", read_n p1, 8
      assert.equals 1, #w.pending_queries["10.0.0.52"]
      libc.close fd2
      libc.close p1
      libc.close p2
      w.pending_queries["10.0.0.52"] = nil

  describe "sockets et helpers", ->
    it "reply_unknown écrit unknown et ferme le fd", ->
      fd, peer = mk_pair!
      w.reply_unknown fd
      assert.equals "unknown\n", read_n peer, 8
      assert.equals -1, libc.close fd
      libc.close peer

    it "set_recv_timeout borne le recv (y compris fd invalide, sans erreur)", ->
      fd, peer = mk_pair!
      w.set_recv_timeout fd, 0.05
      w.set_recv_timeout -1, 0.05   -- échec best-effort ignoré
      assert.equals 0, libc.close fd
      libc.close peer

    it "ensure_parent_dir crée l'arborescence et échoue proprement", ->
      os.execute "rm -rf tmp/mac_learner_core"
      assert.is_true w.ensure_parent_dir "tmp/mac_learner_core/sub/file.sock"
      -- Un parent qui est un fichier fait échouer mkdir.
      os.execute "mkdir -p tmp/mac_learner_core 2>/dev/null && : > tmp/mac_learner_core/afile"
      assert.is_false w.ensure_parent_dir "tmp/mac_learner_core/afile/x.sock"
      -- Chemin sans répertoire parent : rien à faire.
      assert.is_true w.ensure_parent_dir "sock"
      os.execute "rm -rf tmp/mac_learner_core"

    it "create_server crée une socket Unix écoutante puis remplace une socket fantôme", ->
      os.execute "rm -rf tmp/mac_learner_core"
      path = "tmp/mac_learner_core/query.sock"
      fd = w.create_server path
      assert.is_true fd >= 0
      -- Deuxième appel : unlink de la socket existante puis recréation.
      fd2 = w.create_server path
      assert.is_true fd2 >= 0
      libc.close fd
      libc.close fd2
      os.execute "rm -rf tmp/mac_learner_core"

    it "create_server échoue si le répertoire parent est inutilisable", ->
      os.execute "rm -rf tmp/mac_learner_core && mkdir -p tmp/mac_learner_core 2>/dev/null && : > tmp/mac_learner_core/afile"
      assert.equals -1, w.create_server "tmp/mac_learner_core/afile/x.sock"
      os.execute "rm -rf tmp/mac_learner_core"

  describe "run() avec libc simulé", ->
    it "boucle poll : lit un learn, accepte sans client, purge, puis sort", ->
      poll_calls = 0
      reads = 0
      msg = learn_msg (ip4_16 10, 0, 0, 60), "02:00:00:00:00:60"
      fake = {
        unlink: -> 0
        socket: -> 77
        bind: -> 0
        listen: -> 0
        accept: -> -1
        read: (fd, buf, n) ->
          reads += 1
          if reads == 1
            ffi.copy buf, msg, #msg
            #msg
          else
            0
        send: (fd, buf, n) -> n
        close: -> 0
        setsockopt: -> 0
        poll: (pfds, nfds, ms) ->
          poll_calls += 1
          if poll_calls == 1
            pfds[0].revents = POLLIN
            pfds[1].revents = POLLIN
            1
          else
            error "stop-run"
      }
      old_defs = package.loaded["ffi_defs"]
      cfg = package.loaded["config"]
      old_sock = cfg.MAC_LEARNER_QUERY_SOCK
      os.execute "rm -rf tmp/mac_learner_run"
      cfg.MAC_LEARNER_QUERY_SOCK = "tmp/mac_learner_run/query.sock"
      package.loaded["ffi_defs"] = { :ffi, libc: fake, libnfq: {}, libnft: {} }
      package.loaded["mac_learner"] = nil
      w2 = require "mac_learner"
      ok, err = pcall -> w2.run 10, "br-test"
      package.loaded["ffi_defs"] = old_defs
      cfg.MAC_LEARNER_QUERY_SOCK = old_sock
      os.execute "rm -rf tmp/mac_learner_run"
      assert.is_false ok
      assert.is_truthy tostring(err)\match "stop%-run"
      assert.equals 2, poll_calls
      assert.is_true reads >= 2

    it "boucle poll : prober ARP/NS, pipes VLAN/strip et accept d'un client", ->
      poll_calls = 0
      client_fd, client_peer = mk_pair!
      arp_frame = string.rep "\1", 42
      na_frame = string.rep "\2", 86
      vlan_msg = (ip4_16 10, 0, 0, 62) .. "\0\7"
      strip_msg = (require "strip_codec").encode "run.example", 28
      learn = learn_msg (ip4_16 10, 0, 0, 61), "02:00:00:00:00:61"
      req = "10.0.0.70\n"
      learn_reads = 0
      vlan_reads = 0
      strip_reads = 0
      fake = {
        unlink: -> 0
        socket: -> 77
        bind: -> 0
        listen: -> 0
        accept: -> client_fd
        read: (fd, buf, n) ->
          if fd == 90
            vlan_reads += 1
            if vlan_reads == 1
              ffi.copy buf, vlan_msg, #vlan_msg
              return #vlan_msg
            return 0
          if fd == 91
            strip_reads += 1
            if strip_reads == 1
              ffi.copy buf, strip_msg, #strip_msg
              return #strip_msg
            return 0
          learn_reads += 1
          if learn_reads == 1
            ffi.copy buf, learn, #learn
            return #learn
          0
        recv: (fd, buf, n, flags) ->
          if fd == client_fd
            ffi.copy buf, req, #req
            return #req
          frame = (fd == 80) and arp_frame or na_frame
          ffi.copy buf, frame, #frame
          #frame
        send: (fd, buf, n) -> n
        close: -> 0
        setsockopt: -> 0
        poll: (pfds, nfds, ms) ->
          poll_calls += 1
          if poll_calls == 1
            for i = 0, nfds - 1
              pfds[i].revents = POLLIN
            1
          else
            error "stop-run-2"
      }
      mp_stub.init = ->
        { arp_fd: 80, ip6_fd: 81 }
      mp_stub.parse_arp_frame = -> "10.0.0.63", "02:00:00:00:00:63"
      mp_stub.parse_na_frame = -> "2001:db8::64", "02:00:00:00:00:64"
      -- Une requête en attente force poll_ms = 20 et expire_pending dans run().
      now_ms = 100000
      w.pending_queries["10.0.0.99"] = { { 88, 0 } }

      old_defs = package.loaded["ffi_defs"]
      cfg = package.loaded["config"]
      old_sock = cfg.MAC_LEARNER_QUERY_SOCK
      os.execute "rm -rf tmp/mac_learner_run"
      cfg.MAC_LEARNER_QUERY_SOCK = "tmp/mac_learner_run/query.sock"
      package.loaded["ffi_defs"] = { :ffi, libc: fake, libnfq: {}, libnft: {} }
      package.loaded["mac_learner"] = nil
      w2 = require "mac_learner"
      ok, err = pcall -> w2.run 10, "br-test", 90, 91
      package.loaded["ffi_defs"] = old_defs
      cfg.MAC_LEARNER_QUERY_SOCK = old_sock
      os.execute "rm -rf tmp/mac_learner_run"
      libc.close client_peer
      assert.is_false ok
      assert.is_truthy tostring(err)\match "stop%-run%-2"
      assert.equals 2, poll_calls
      assert.equals 0, learn_reads - 2   -- 2 lectures : message puis EOF
