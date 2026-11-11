-- tests/unit/bridge_raw_spec.moon
-- T5 : bridge_raw — ouverture du socket AF_PACKET (protocole 0, sans capture),
-- émission de trames et lecture de la MAC depuis sysfs.
-- lib.socket est stubbé localement pour éviter tout socket réel.

ffi = require "ffi"

-- Charge le vrai lib.socket d'abord : déclare struct sockaddr_ll (utilisé par
-- send) avant que le stub ne remplace le module.
pcall require, "lib.socket"

orig_socket = package.loaded["lib.socket"]
orig_bridge = package.loaded["bridge_raw"]
orig_io_open = io.open

socket_calls = {}
send_calls = {}
state = {}

package.loaded["lib.socket"] = {
  C: {
    socket: (domain, type, proto) ->
      socket_calls[#socket_calls + 1] = { :domain, :type, :proto }
      state.socket_ret
    sendto: (fd, frame, len, flags, addr, addrlen) ->
      sll = ffi.cast "const struct sockaddr_ll*", addr
      send_calls[#send_calls + 1] = {
        :fd, :len, frame: ffi.string(frame, len)
        family: sll.sll_family
        protocol: sll.sll_protocol
        ifindex: sll.sll_ifindex
      }
      state.send_ret
  }
  AF_PACKET: 17
  SOCK_RAW: 3
  ETH_P_ALL: 3
}
package.loaded["bridge_raw"] = nil
br = require "bridge_raw"

MAC_STR   = "aa:bb:cc:dd:ee:ff\n"
MAC_BYTES = "\170\187\204\221\238\255"

fake_sysfs = (content) ->
  fh = {
    read: (self, fmt) -> content
    close: (self) -> nil
  }
  (path, mode) ->
    if path == "/sys/class/net/fake0/address"
      return nil if content == nil
      fh
    else
      nil

describe "bridge_raw", ->
  teardown ->
    package.loaded["lib.socket"] = orig_socket
    package.loaded["bridge_raw"] = orig_bridge
    io.open = orig_io_open

  before_each ->
    socket_calls = {}
    send_calls = {}
    state = {}

  describe "read_mac", ->
    it "décode la MAC sysfs (hexadécimal séparé par ':')", ->
      io.open = fake_sysfs MAC_STR
      assert.equals MAC_BYTES, br.read_mac "fake0"

    it "retourne nil quand l'interface n'existe pas", ->
      io.open = fake_sysfs nil
      assert.is_nil br.read_mac "fake0"

    it "retourne nil pour un fichier vide", ->
      io.open = fake_sysfs ""
      assert.is_nil br.read_mac "fake0"

  describe "open_socket", ->
    it "ouvre un socket AF_PACKET/SOCK_RAW de protocole 0 (sans capture)", ->
      state.socket_ret = 9
      fd, err = br.open_socket "br0"
      assert.equals 9, fd
      assert.is_nil err
      assert.equals 1, #socket_calls
      assert.equals 17, socket_calls[1].domain   -- AF_PACKET
      assert.equals 3, socket_calls[1].type      -- SOCK_RAW
      assert.equals 0, socket_calls[1].proto     -- proto 0 : aucun paquet capturé

    it "retourne nil et un message d'erreur si socket() échoue", ->
      state.socket_ret = -1
      fd, err = br.open_socket "br0"
      assert.is_nil fd
      assert.is_not_nil err
      assert.is_not_nil err\match "^socket%(%) failed on br0: errno %d+$"

  describe "send", ->
    it "émet la trame sur l'interface et le protocole ETH_P_ALL", ->
      frame = string.rep "\0", 60
      state.send_ret = 60
      assert.is_true br.send 9, frame, 7
      assert.equals 1, #send_calls
      call = send_calls[1]
      assert.equals 9, call.fd
      assert.equals 60, call.len
      assert.equals 7, call.ifindex
      assert.equals 17, call.family
      assert.equals 3, call.protocol
      assert.equals frame, call.frame

    it "retourne false sur envoi partiel", ->
      state.send_ret = 59
      assert.is_false br.send 9, string.rep("\0", 60), 7
