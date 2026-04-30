-- src/bridge_raw.moon
-- Socket AF_PACKET/SOCK_RAW pour injection de trames Ethernet sur un bridge.
-- Factorisé pour être partagé entre worker_captive (Q2, redirections TCP) et
-- worker_questions (Q0, réponses DNS forgées).

{ :ffi, :libc } = require "ffi_defs"
{ :s2mac }      = require "ipparse.l2.ethernet"

AF_PACKET = 17
SOCK_RAW  = 3
ETH_P_ALL = 0x0300   -- htons(ETH_P_ALL = 0x0003)

--- Ouvre un socket AF_PACKET/SOCK_RAW non lié.
-- @tparam  string     ifname Nom de l'interface (pour le message d'erreur uniquement)
-- @treturn number|nil        fd du socket, ou nil en cas d'erreur
-- @treturn nil|string        Message d'erreur
open_socket = (ifname) ->
  fd = libc.socket AF_PACKET, SOCK_RAW, ETH_P_ALL
  return nil, "socket() failed on #{ifname}: errno #{ffi.errno!}" if fd < 0
  fd, nil

--- Lit l'adresse MAC d'une interface depuis sysfs.
-- @tparam  string     ifname Nom de l'interface (ex. "br")
-- @treturn string|nil        MAC brut (6 octets), ou nil si introuvable
read_mac = (ifname) ->
  fh = io.open "/sys/class/net/#{ifname}/address", "r"
  return nil unless fh
  mac_str = fh\read("*a")\gsub "\n", ""
  fh\close!
  return nil unless mac_str and #mac_str > 0
  s2mac mac_str

--- Envoie une trame Ethernet brute sur un socket AF_PACKET.
-- @tparam  number  fd      fd du socket ouvert par open_socket()
-- @tparam  string  frame   Trame Ethernet sérialisée (octets bruts)
-- @tparam  number  ifindex Index de l'interface de sortie
-- @treturn boolean         true si tous les octets ont été envoyés
send = (fd, frame, ifindex) ->
  sll = ffi.new "struct sockaddr_ll"
  ffi.fill sll, ffi.sizeof(sll), 0
  sll.sll_family   = AF_PACKET
  sll.sll_protocol = ETH_P_ALL
  sll.sll_ifindex  = ifindex
  n = libc.sendto fd, frame, #frame, 0,
    ffi.cast("const struct sockaddr*", sll), ffi.sizeof(sll)
  n == #frame

{ :open_socket, :read_mac, :send }
