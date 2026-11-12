-- tests/unit/mac_prober_socket_spec.moon
-- Couverture des chemins socket du sondeur MAC (init, open_socket, send_frame,
-- wait_reply, probe_and_wait, send_probe) et des lectures sysfs /proc, hors
-- des helpers purs déjà couverts par tests/unit/mac_prober_spec.moon.
--
-- Aucun accès root : `lib.socket` est remplacé par un C simulé après avoir
-- chargé le vrai module (pour disposer des cdefs struct sockaddr_ll/pollfd).

ffi = require "ffi"
pcall ffi.cdef "int* __errno_location(void);"

mp = require "mac_prober"
REAL_SOCKET = package.loaded["lib.socket"]
REAL_MP = package.loaded["mac_prober"]
REAL_IO_OPEN = io.open

OUR_MAC = "\170\187\204\221\238\255"
OUR_IP6 = "\254\128" .. string.rep("\0", 13) .. "\1"

fake_C = nil
sock_fds = nil
bind_rc = 0
sendto_n = nil
poll_rc = 0
recv_frames = nil
ifindex = 5

install_fake_C = ->
  fake_C = {
    htons: (v) -> v
    inet_pton: (af, s, buf) -> ffi.C.inet_pton af, s, buf
    socket: ->
      return -1 if #sock_fds == 0
      table.remove sock_fds, 1
    bind: -> bind_rc
    if_nametoindex: -> ifindex
    sendto: (fd, frame, len, flags, addr, addrlen) ->
      return sendto_n if sendto_n != nil
      len
    poll: (pfd, n, ms) ->
      if poll_rc != 0 and pfd[0]
        pfd[0].revents = 1
      poll_rc
    recv: (fd, buf, n, flags) ->
      return 0 unless recv_frames and #recv_frames > 0
      frame = table.remove recv_frames, 1
      ffi.copy buf, frame, #frame
      #frame
  }
  package.loaded["lib.socket"] = { C: fake_C, AF_PACKET: 17, SOCK_RAW: 3, AF_INET6: 10 }
  package.loaded["mac_prober"] = nil
  require "mac_prober"

fake_io_open = (proc_lines) ->
  real_open = io.open
  io.open = (path, mode) ->
    if path == "/proc/net/if_inet6"
      idx = 0
      return {
        lines: ->
          ->
            idx += 1
            proc_lines[idx]
        close: -> nil
      }
    real_open path, mode

describe "mac_prober sockets", ->
  before_each ->
    sock_fds = { 10, 11 }
    bind_rc = 0
    sendto_n = nil
    poll_rc = 0
    recv_frames = nil
    ifindex = 5

  after_each ->
    package.loaded["lib.socket"] = REAL_SOCKET
    package.loaded["mac_prober"] = REAL_MP

  describe "get_ms", ->
    it "renvoie un temps monotone croissant en millisecondes", ->
      a = mp.get_ms!
      b = mp.get_ms!
      assert.is_number a
      assert.is_true a > 0
      assert.is_true b >= a

  describe "read_own_mac / read_own_ip6", ->
    it "lit la MAC sysfs d'une interface réelle, nil si absente", ->
      mac = mp.read_own_mac "lo"
      assert.equals 6, #mac
      assert.is_nil mp.read_own_mac "interface-inexistante-xyz"

    it "lit l'IPv6 link-local (scope 20) de l'interface demandée", ->
      fake_io_open {
        "fe800000000000000000000000000001 01 40 20 80 lo"
        "20010db8000000000000000000000001 01 40 00 80 lo"
      }
      ip6 = mp.read_own_ip6 "lo"
      io.open = REAL_IO_OPEN
      assert.equals OUR_IP6, ip6

    it "ignore les autres interfaces et les scopes non link-local", ->
      fake_io_open {
        "fe800000000000000000000000000002 01 40 20 80 eth0"
        "20010db8000000000000000000000001 01 40 00 80 lo"
      }
      assert.is_nil mp.read_own_ip6 "lo"
      io.open = REAL_IO_OPEN

  describe "open_socket et send_frame", ->
    before_each ->
      install_fake_C!

    it "open_socket renvoie le fd ou nil selon socket()/bind()", ->
      w = package.loaded["mac_prober"]
      assert.equals 10, w.open_socket 0x0806, 5
      sock_fds = { 10 }
      bind_rc = -1
      w2 = install_fake_C!
      assert.is_nil w2.open_socket 0x0806, 5
      sock_fds = {}
      w3 = install_fake_C!
      assert.is_nil w3.open_socket 0x0806, 5

    it "send_frame compare les octets émis à la longueur de la trame", ->
      w = package.loaded["mac_prober"]
      assert.is_true w.send_frame 10, 5, "abc"
      sendto_n = 2
      assert.is_false w.send_frame 10, 5, "abc"

  describe "wait_reply", ->
    before_each -> install_fake_C!

    it "retourne la MAC dès qu'une trame satisfait parse_fn", ->
      w = package.loaded["mac_prober"]
      poll_rc = 1
      recv_frames = { "frame" }
      mac = w.wait_reply 10, 100, (raw, n) -> "02:00:00:00:00:01"
      assert.equals "02:00:00:00:00:01", mac

    it "ignore les trames non satisfaisantes puis expire", ->
      w = package.loaded["mac_prober"]
      recv_frames = { "noise" }
      polls = 0
      fake_C.poll = (pfd, n, ms) ->
        polls += 1
        if polls == 1
          pfd[0].revents = 1
          return 1
        0
      calls = 0
      mac = w.wait_reply 10, 100, (raw, n) ->
        calls += 1
        nil
      assert.is_nil mac
      assert.equals 1, calls

    it "poll à 0 (timeout) → nil immédiat", ->
      w = package.loaded["mac_prober"]
      poll_rc = 0
      assert.is_nil w.wait_reply 10, 100, -> "jamais"

  describe "init", ->
    before_each -> install_fake_C!

    it "initialise le contexte ARP (pas d'IPv6 link-local sur lo)", ->
      w = package.loaded["mac_prober"]
      ctx = w.init "lo"
      assert.is_not_nil ctx
      assert.equals 10, ctx.arp_fd
      assert.is_nil ctx.ip6_fd
      assert.equals 6, #ctx.our_mac

    it "active les sondes NS quand une IPv6 link-local existe", ->
      fake_io_open { "fe800000000000000000000000000001 01 40 20 80 lo" }
      w = install_fake_C!
      ctx = w.init "lo"
      io.open = REAL_IO_OPEN
      assert.is_not_nil ctx
      assert.equals 11, ctx.ip6_fd

    it "échoue si la MAC, l'ifindex ou le socket ARP manque", ->
      w = package.loaded["mac_prober"]
      assert.is_nil w.init "interface-inexistante-xyz"
      ifindex = 0
      w2 = install_fake_C!
      assert.is_nil w2.init "lo"
      ifindex = 5
      sock_fds = {}
      w3 = install_fake_C!
      assert.is_nil w3.init "lo"

    it "socket IPv6 indisponible → contexte ARP seul", ->
      fake_io_open { "fe800000000000000000000000000001 01 40 20 80 lo" }
      sock_fds = { 10 }   -- un seul fd : le socket IPv6 échoue
      w = install_fake_C!
      ctx = w.init "lo"
      io.open = REAL_IO_OPEN
      assert.is_not_nil ctx
      assert.is_nil ctx.ip6_fd

  describe "probe_and_wait et send_probe", ->
    before_each -> install_fake_C!

    it "ARP : envoie puis attend une réponse (timeout ici)", ->
      w = package.loaded["mac_prober"]
      ctx = { arp_fd: 10, ifindex: 5, our_mac: OUR_MAC }
      poll_rc = 0
      assert.is_nil w.probe_and_wait ctx, "192.0.2.10", 50

    it "ARP : échec d'envoi → nil", ->
      w = package.loaded["mac_prober"]
      ctx = { arp_fd: 10, ifindex: 5, our_mac: OUR_MAC }
      sendto_n = -1
      assert.is_nil w.probe_and_wait ctx, "192.0.2.10", 50

    it "NS IPv6 : envoie puis attend (timeout ici)", ->
      w = package.loaded["mac_prober"]
      ctx = { ip6_fd: 11, ifindex: 5, our_mac: OUR_MAC, our_ip6: OUR_IP6 }
      poll_rc = 0
      assert.is_nil w.probe_and_wait ctx, "2001:db8::1", 50

    it "cas d'indisponibilité : ctx nil, cible invalide, IPv6 sans socket", ->
      w = package.loaded["mac_prober"]
      assert.is_nil w.probe_and_wait nil, "192.0.2.10", 50
      assert.is_nil w.probe_and_wait({ arp_fd: 10, ifindex: 5 }, "pas-une-ip", 50)
      assert.is_nil w.probe_and_wait({ arp_fd: 10, ifindex: 5 }, "2001:db8::1", 50)

    it "send_probe renvoie le résultat d'envoi, false sur indisponibilité", ->
      w = package.loaded["mac_prober"]
      ctx = { arp_fd: 10, ip6_fd: 11, ifindex: 5, our_mac: OUR_MAC, our_ip6: OUR_IP6 }
      assert.is_true w.send_probe ctx, "192.0.2.10"
      assert.is_true w.send_probe ctx, "2001:db8::1"
      sendto_n = -1
      assert.is_false w.send_probe ctx, "192.0.2.10"
      assert.is_false w.send_probe ctx, "pas-une-ip"
      assert.is_false w.send_probe { arp_fd: 10, ifindex: 5, our_mac: OUR_MAC }, "2001:db8::1"
      assert.is_false w.send_probe nil, "192.0.2.10"

  describe "checksum sur payload impair", ->
    it "ones_add gère l'octet final non apparié", ->
      -- 1 octet : couvre la branche `acc += s:byte(i) * 256 if i == n`.
      ck = mp.icmpv6_cksum OUR_IP6, OUR_IP6, "A"
      assert.is_number ck
      ck2 = mp.icmpv6_cksum OUR_IP6, OUR_IP6, "AB"
      assert.is_number ck2
      assert.not_equals ck, ck2
