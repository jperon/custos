-- tests/unit/worker_arp_sniffer_core_spec.moon
-- Couverture des parseurs de trames (ARP IPv4, NDP NS/NA), de la construction
-- du message IPC 22 octets et de la boucle run() restés hors du spec BPF.
--
-- Les parseurs écrivent dans un vrai pipe (aucun root). Pour open_socket/
-- attach_filter/run, `lib.socket` est remplacé par un C simulé (les cdefs sont
-- d'abord déclarées en chargeant le vrai module).

ffi = require "ffi"
bit = require "bit"
sp = require("ipparse.lib.pack_compat").pack
{ :libc } = require "ffi_defs"

pcall ffi.cdef "int pipe(int pipefd[2]);"
pcall ffi.cdef "long read(int fd, void *buf, unsigned long count);"
pcall ffi.cdef "int* __errno_location(void);"
pcall ffi.cdef "struct sock_filter { uint16_t code; uint8_t jt; uint8_t jf; uint32_t k; };"
pcall ffi.cdef "struct sock_fprog { unsigned short len; struct sock_filter *filter; };"
pcall ffi.cdef [[
  struct packet_mreq {
    int            mr_ifindex;
    unsigned short mr_type;
    unsigned short mr_alen;
    unsigned char  mr_address[8];
  };
]]

wa = require "worker_arp_sniffer"
REAL_SOCKET = package.loaded["lib.socket"]
REAL_WA = package.loaded["worker_arp_sniffer"]

-- ── Trames ─────────────────────────────────────────────────────────
OUR_MAC = "\170\187\204\221\238\255"       -- aa:bb:cc:dd:ee:ff
SRC_MAC = "\2\0\0\0\0\1"                   -- 02:00:00:00:00:01
TGT_IP4 = "\192\0\2\10"                    -- 192.0.2.10
TGT_IP6 = "\32\1\13\184" .. string.rep("\0", 10) .. "\202\254"

eth = (ethertype) ->
  dst = string.rep "\255", 6
  hi = math.floor ethertype / 256
  lo = ethertype % 256
  dst .. SRC_MAC .. string.char(hi, lo)

arp_frame = (sha=SRC_MAC, spa=TGT_IP4, opts={}) ->
  eth(0x0806) .. "\0\1\8\0\6\4" .. sp(">H", opts.op or 2) ..
    sha .. spa .. string.rep("\0", 6) .. TGT_IP4

ipv6_frame = (icmp_type, opts={}) ->
  next_hdr = opts.next_hdr or 58
  src6 = opts.src6 or (string.rep("\254\128", 1) .. string.rep("\0", 13) .. "\1")
  target = opts.target or TGT_IP6
  body = string.char(icmp_type, 0, 0, 0) .. "\0\0\0\0" .. target
  body = body .. string.char(2, 1) .. (opts.tlla or SRC_MAC) if opts.tlla != false
  hdr = string.char(0x60, 0, 0, 0) .. sp(">H B B", #body, next_hdr, 64) .. src6 .. TGT_IP6
  -- padding : octet de bourrage optionnel après les options NDP.
  eth(0x86DD) .. hdr .. body .. string.rep("\0", opts.padding or 0)

with_pipe = (fn) ->
  fds = ffi.new "int[2]"
  assert.equals 0, libc.pipe fds
  fn fds[1], ->
    libc.close fds[1]
    buf = ffi.new "uint8_t[64]"
    n = libc.read fds[0], buf, 64
    libc.close fds[0]
    if n and n > 0
      ffi.string buf, n
    else
      nil

describe "worker_arp_sniffer cœur", ->
  after_each -> collectgarbage "collect"
  describe "build_learn_msg et write_learn", ->
    it "encode IPv4 (4 octets + 12 zéros) puis la MAC source", ->
      frame = arp_frame!
      msg = wa.build_learn_msg frame, 29, 4, 7
      assert.is_not_nil msg
      raw = ffi.string msg, 22
      assert.equals TGT_IP4, raw\sub 1, 4
      assert.equals string.rep("\0", 12), raw\sub 5, 16
      assert.equals SRC_MAC, raw\sub 17, 22

    it "encode une IPv6 complète", ->
      frame = ipv6_frame 136
      msg = wa.build_learn_msg frame, 63, 16, 7
      raw = ffi.string msg, 22
      assert.equals TGT_IP6, raw\sub 1, 16
      assert.equals SRC_MAC, raw\sub 17, 22

    it "renvoie nil si encode_ip16 refuse la longueur", ->
      assert.is_nil wa.build_learn_msg (arp_frame!), 29, 3, 7

    it "write_learn écrit 22 octets et signale l'échec sur fd fermé", ->
      with_pipe (wfd, read_all) ->
        msg = wa.build_learn_msg (arp_frame!), 29, 4, 7
        assert.is_true wa.write_learn wfd, msg
        assert.equals 22, #read_all!
      assert.is_false wa.write_learn -1, wa.build_learn_msg(arp_frame!, 29, 4, 7)

  describe "extract_tlla", ->
    opt = (type, len_units, mac) -> string.char(type, len_units) .. mac

    it "retourne la MAC d'une option TLLA valide", ->
      -- Un octet de bourrage après l'option (comme sur une trame Ethernet
      -- complétée) : cf. test pending sur la trame exactement remplie.
      raw = string.rep("\0", 78) .. opt(2, 1, SRC_MAC) .. "\0"
      assert.equals SRC_MAC, wa.extract_tlla raw, 79, #raw

    it "ignore les autres options et une TLLA nulle", ->
      raw = string.rep("\0", 78) .. opt(1, 1, SRC_MAC) .. opt(2, 1, string.rep("\0", 6)) .. opt(2, 1, SRC_MAC) .. "\0"
      assert.equals SRC_MAC, wa.extract_tlla raw, 79, #raw

    it "rejette une option invalide (longueur 0 ou >255 unités)", ->
      raw = string.rep("\0", 78) .. opt(2, 0, SRC_MAC) .. string.rep("\0", 8)
      assert.is_nil wa.extract_tlla raw, 79, #raw
      raw2 = string.rep("\0", 78) .. opt(2, 40, SRC_MAC)
      assert.is_nil wa.extract_tlla raw2, 79, #raw2

    it "rejette une option tronquée et une trame trop courte", ->
      raw = string.rep("\0", 78) .. opt(2, 2, SRC_MAC)   -- annonce 16 octets
      assert.is_nil wa.extract_tlla raw, 79, #raw
      assert.is_nil wa.extract_tlla (string.rep "\0", 80), 79, 80

  describe "process_arp", ->
    it "écrit un message learn pour une trame ARP IPv4 valide", ->
      with_pipe (wfd, read_all) ->
        frame = arp_frame!
        wa.process_arp frame, #frame, wfd
        raw = assert read_all!
        assert.equals 22, #raw
        assert.equals TGT_IP4, raw\sub 1, 4
        assert.equals SRC_MAC, raw\sub 17, 22

    it "ignore trame courte, mauvais type, ou MAC nulle", ->
      with_pipe (wfd, read_all) ->
        frame = arp_frame!
        wa.process_arp frame, 41, wfd
        wa.process_arp (frame\sub(1, 14) .. "\0\2" .. frame\sub 17), #frame, wfd
        base = arp_frame!
        zero = base\sub(1, 6) .. string.rep("\0", 6) .. base\sub 13
        wa.process_arp zero, #zero, wfd
        assert.is_nil read_all!

  describe "process_ipv6", ->
    it "NS : apprend la source IPv6 + MAC Ethernet", ->
      with_pipe (wfd, read_all) ->
        frame = ipv6_frame 135
        wa.process_ipv6 frame, #frame, wfd
        raw = assert read_all!
        assert.equals string.rep("\254\128", 1) .. string.rep("\0", 13) .. "\1", raw\sub 1, 16
        assert.equals SRC_MAC, raw\sub 17, 22

    it "NA avec TLLA : apprend la Target Address + MAC TLLA", ->
      with_pipe (wfd, read_all) ->
        frame = ipv6_frame 136, tlla: "\6\5\4\3\2\1", padding: 1
        wa.process_ipv6 frame, #frame, wfd
        raw = assert read_all!
        assert.equals TGT_IP6, raw\sub 1, 16
        assert.equals "\6\5\4\3\2\1", raw\sub 17, 22

    it "NA sans TLLA : repli sur la MAC source Ethernet", ->
      with_pipe (wfd, read_all) ->
        frame = ipv6_frame 136, tlla: false
        wa.process_ipv6 frame, #frame, wfd
        raw = assert read_all!
        assert.equals TGT_IP6, raw\sub 1, 16
        assert.equals SRC_MAC, raw\sub 17, 22

    it "ignore NS multicast, DAD et les trames non NDP", ->
      with_pipe (wfd, read_all) ->
        multicast = ipv6_frame 135, src6: "\255\2" .. string.rep("\0", 14)
        wa.process_ipv6 multicast, #multicast, wfd
        dad = ipv6_frame 135, src6: string.rep("\0", 16)
        wa.process_ipv6 dad, #dad, wfd
        wa.process_ipv6 (ipv6_frame 128), #(ipv6_frame 128), wfd
        wa.process_ipv6 (ipv6_frame 135, next_hdr: 6), #(ipv6_frame 135, next_hdr: 6), wfd
        wa.process_ipv6 (string.rep "\0", 55), 55, wfd
        assert.is_nil read_all!

    it "ignore une MAC source nulle et une cible NA multicast", ->
      with_pipe (wfd, read_all) ->
        zero_mac = ipv6_frame 135, tlla: string.rep("\0", 6)
        -- La MAC source Ethernet est SRC_MAC : reconstruire une trame à MAC nulle.
        frame = ipv6_frame 135
        frame = frame\sub(1, 6) .. string.rep("\0", 6) .. frame\sub 13
        wa.process_ipv6 frame, #frame, wfd
        na_mcast = ipv6_frame 136, target: "\255" .. string.rep("\0", 15)
        wa.process_ipv6 na_mcast, #na_mcast, wfd
        assert.is_nil read_all!

  describe "sockets simulés : open_socket et attach_filter", ->
    sock_rc = 0
    bind_rc = 0
    opt_rc = 0
    fake_C = nil
    wa2 = nil

    before_each ->
      sock_rc = 10
      bind_rc = 0
      opt_rc = 0
      fake_C = {
        htons: (v) -> v
        socket: -> sock_rc
        bind: -> bind_rc
        setsockopt: -> opt_rc
        if_nametoindex: -> 5
      }
      package.loaded["lib.socket"] = { C: fake_C, AF_PACKET: 17, SOCK_RAW: 3 }
      package.loaded["worker_arp_sniffer"] = nil
      wa2 = require "worker_arp_sniffer"

    after_each ->
      package.loaded["lib.socket"] = REAL_SOCKET
      package.loaded["worker_arp_sniffer"] = REAL_WA

    it "open_socket renvoie le fd, attache BPF et active le promiscuous", ->
      assert.equals 10, wa2.open_socket 5
      assert.is_true wa2.attach_filter 10
      opt_rc = -1
      -- Échecs best-effort : BPF et promiscuous ne bloquent pas l'ouverture.
      assert.is_false wa2.attach_filter 10

    it "open_socket renvoie nil si socket() ou bind() échoue", ->
      sock_rc = -1
      assert.is_nil wa2.open_socket 5
      sock_rc = 10
      bind_rc = -1
      assert.is_nil wa2.open_socket 5

  describe "run() avec C simulé", ->
    fake_C = nil
    wa2 = nil
    frames = {}
    ifindex = 5
    opt_rc = 0
    poll_calls = 0
    errs = {}
    last_frame = nil

    before_each ->
      frames = {}
      ifindex = 5
      opt_rc = 0
      poll_calls = 0
      errs = {}
      last_frame = nil
      fake_C = {
        htons: (v) -> v
        socket: -> 10
        bind: -> 0
        setsockopt: -> opt_rc
        if_nametoindex: (name) -> if name == "br0" then ifindex else 0
        poll: (pfds, nfds, ms) ->
          poll_calls += 1
          if #frames == 0
            return 0
          frame = table.remove frames, 1
          last_frame = frame
          pfds[0].revents = 1
          return 1
        recv: (fd, buf, n, flags) ->
          ffi.copy buf, last_frame, #last_frame
          #last_frame
      }
      package.loaded["lib.socket"] = { C: fake_C, AF_PACKET: 17, SOCK_RAW: 3 }
      package.loaded["worker_arp_sniffer"] = nil
      wa2 = require "worker_arp_sniffer"

    after_each ->
      package.loaded["lib.socket"] = REAL_SOCKET
      package.loaded["worker_arp_sniffer"] = REAL_WA

    it "ignore un ifindex introuvable et retourne sans socket", ->
      ifindex = 0
      assert.is_nil wa2.run "brX", 99

    -- Les tests de boucle avec socket sont marqués pending dans
    -- worker_arp_sniffer_bugs_spec.moon : run() écrit hors bornes du tableau
    -- pollfd (voir ce fichier), ce qui corrompt la mémoire du processus de
    -- test. Seul le retour anticipé sans socket est donc exécuté ici.
