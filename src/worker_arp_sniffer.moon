-- src/worker_arp_sniffer.moon
-- Worker passif d'apprentissage IP→MAC par écoute ARP et NDP.
--
-- Ouvre deux sockets AF_PACKET/SOCK_RAW liés à l'interface bridge :
--   • arp_fd  : EtherType 0x0806 (ARP) — le noyau filtre, on ne reçoit que des ARP
--   • ip6_fd  : EtherType 0x86DD (IPv6) — filtrage NDP en Lua (ICMPv6 type 135/136)
--
-- Chaque association IP→MAC découverte est écrite dans le pipe learn
-- (format binaire 22 octets : ip16 + mac6), identique au format de
-- worker_questions et worker_auth_queue, consommé par mac_learner.
--
-- Aucune modification de paquet, aucun verdict NFQUEUE, aucune règle nftables.

{ :ffi, :libc } = require "ffi_defs"
{ :C, :AF_PACKET, :SOCK_RAW, :AF_INET6 } = require "lib.socket"
{ :log_info, :log_warn, :log_debug, :set_action_prefix } = require "log"

-- ── Constantes réseau ────────────────────────────────────────────

POLLIN     = 1

-- htons() pour les protocoles passés à socket() :
-- AF_PACKET reçoit le protocole en network byte order.
ETH_P_ARP  = C.htons 0x0806   -- ARP
ETH_P_IPV6 = C.htons 0x86DD   -- IPv6

-- ICMPv6 next-header number et types NDP
ICMPV6_PROTO        = 58
ICMPV6_TYPE_NS      = 135   -- Neighbor Solicitation
ICMPV6_TYPE_NA      = 136   -- Neighbor Advertisement

-- Taille minimale des trames attendues (octets, base 1 Lua)
ARP_MIN_LEN  = 42    -- 14 (Eth) + 28 (ARP IPv4/Ethernet)
NDP_MIN_LEN  = 56    -- 14 (Eth) + 40 (IPv6) + 2 (ICMPv6 type+code)

-- ── Helpers ──────────────────────────────────────────────────────

--- Formate 6 octets d'une chaîne Lua en "aa:bb:cc:dd:ee:ff" (pour les logs).
-- @tparam string s  Chaîne d'au moins 6 octets
-- @tparam number o  Offset 1-based du premier octet dans s
-- @treturn string Adresse MAC formatée
fmt_mac = (s, o) ->
  string.format "%02x:%02x:%02x:%02x:%02x:%02x",
    s\byte(o), s\byte(o+1), s\byte(o+2),
    s\byte(o+3), s\byte(o+4), s\byte(o+5)

--- Formate 16 octets d'une chaîne Lua en adresse IPv6 textuelle (pour les logs).
-- Utilise inet_ntop pour obtenir la forme canonique compressée.
-- @tparam string s  Chaîne d'au moins o+15 octets
-- @tparam number o  Offset 1-based du premier octet dans s
-- @treturn string Adresse IPv6 (ex : "fd00:28::a") ou "?" en cas d'échec
fmt_ipv6 = (s, o) ->
  buf = ffi.new "uint8_t[16]"
  for i = 0, 15
    buf[i] = s\byte(o + i)
  ntop = ffi.new "char[46]"
  rc = C.inet_ntop AF_INET6, buf, ntop, 46
  return "?" if rc == nil
  ffi.string ntop

--- Construit un message binaire 22 octets (ip16 + mac6) pour le pipe learn.
-- @tparam string raw  Trame Ethernet brute (base 1 Lua)
-- @tparam number ip_off   Offset 1-based du premier octet de l'adresse IP dans raw
-- @tparam number ip_len   Longueur de l'adresse IP (4 pour IPv4, 16 pour IPv6)
-- @tparam number mac_off  Offset 1-based du premier octet de la MAC dans raw
-- @treturn cdata  Pointeur vers uint8_t[22] prêt à écrire dans le pipe
build_learn_msg = (raw, ip_off, ip_len, mac_off) ->
  msg = ffi.new "uint8_t[22]"
  -- ip16 : IPv4 dans les 4 premiers octets, 12 zéros de padding
  --        IPv6 occupe les 16 octets entiers
  for i = 0, ip_len - 1
    msg[i] = raw\byte(ip_off + i)
  -- msg[ip_len..15] reste à zéro (ffi.new initialise à 0)
  -- mac6 : bytes 16-21
  for i = 0, 5
    msg[16 + i] = raw\byte(mac_off + i)
  msg

--- Écrit un message d'apprentissage dans le pipe learn.
-- Écriture best-effort : l'échec (pipe plein, fd invalide) est ignoré
-- pour ne jamais bloquer la boucle de sniffing.
-- @tparam number  learn_wfd  fd d'écriture du pipe
-- @tparam cdata   msg        Pointeur uint8_t[22]
-- @treturn boolean true si l'écriture a réussi
write_learn = (learn_wfd, msg) ->
  n = libc.write learn_wfd, msg, 22
  n == 22

-- ── Sockets AF_PACKET ────────────────────────────────────────────

--- Ouvre et lie un socket AF_PACKET/SOCK_RAW à une interface.
-- @tparam number  eth_proto  Protocole réseau (résultat de htons, ex : ETH_P_ARP)
-- @tparam number  ifindex    Index de l'interface (résultat de if_nametoindex)
-- @treturn number|nil  fd du socket, ou nil en cas d'erreur
open_socket = (eth_proto, ifindex) ->
  fd = C.socket AF_PACKET, SOCK_RAW, eth_proto
  if fd < 0
    return nil

  sll = ffi.new "struct sockaddr_ll"
  ffi.fill sll, ffi.sizeof(sll), 0
  sll.sll_family   = AF_PACKET
  sll.sll_protocol = eth_proto
  sll.sll_ifindex  = ifindex

  if C.bind(fd, ffi.cast("struct sockaddr*", sll), ffi.sizeof(sll)) ~= 0
    libc.close fd
    return nil

  fd

-- ── Parseurs de trames ───────────────────────────────────────────

--- Traite une trame ARP et écrit l'association IPv4→MAC dans le pipe.
--
-- Structure de la trame ARP (offset 1-based Lua, EtherType déjà filtré) :
--   1-6   Ethernet dst MAC
--   7-12  Ethernet src MAC  ← MAC cliente
--   13-14 EtherType (0x0806)
--   15-16 ARP hw type       (1 = Ethernet)
--   17-18 ARP proto type    (0x0800 = IPv4)
--   19    hw addr len       (doit être 6)
--   20    proto addr len    (doit être 4)
--   21-22 opération         (1=request, 2=reply)
--   23-28 sender HW addr    (redondant avec bytes 7-12)
--   29-32 sender proto addr ← IPv4 cliente
--
-- @tparam string raw      Trame brute
-- @tparam number len      Longueur utilisable de raw
-- @tparam number learn_wfd  fd du pipe learn
process_arp = (raw, len, learn_wfd) ->
  return if len < ARP_MIN_LEN

  -- Vérifier que c'est bien ARP IPv4/Ethernet
  hw_type    = raw\byte(15) * 256 + raw\byte(16)   -- doit être 1
  proto_type = raw\byte(17) * 256 + raw\byte(18)   -- doit être 0x0800
  hw_len     = raw\byte(19)                         -- doit être 6
  proto_len  = raw\byte(20)                         -- doit être 4

  return unless hw_type == 1 and proto_type == 0x0800 and hw_len == 6 and proto_len == 4

  -- Ignorer les MACs nulles (ne devrait pas arriver en pratique)
  mac_off = 7
  all_zero = true
  for i = 0, 5
    if raw\byte(mac_off + i) ~= 0
      all_zero = false
      break
  return if all_zero

  msg = build_learn_msg raw, 29, 4, mac_off
  ok = write_learn learn_wfd, msg
  log_debug { action: "arp_learned", mac: fmt_mac(raw, mac_off),
    ip: "#{raw\byte 29}.#{raw\byte 30}.#{raw\byte 31}.#{raw\byte 32}" } if ok

--- Traite une trame IPv6 et écrit l'association IPv6→MAC dans le pipe
-- si c'est un NDP Neighbor Solicitation (135) ou Advertisement (136).
--
-- Structure de la trame (offset 1-based Lua, EtherType 0x86DD filtré) :
--   1-6   Ethernet dst MAC
--   7-12  Ethernet src MAC  ← MAC cliente
--   13-14 EtherType (0x86DD)
--   ── IPv6 header (40 octets) ──────────────────────────────────
--   15-20 version / TC / flow label / payload length
--   21    next header       (doit être 58 = ICMPv6)
--   22    hop limit
--   23-38 source IPv6       ← IPv6 cliente
--   39-54 destination IPv6
--   ── ICMPv6 ───────────────────────────────────────────────────
--   55    ICMPv6 type       (doit être 135 ou 136)
--
-- @tparam string raw      Trame brute
-- @tparam number len      Longueur utilisable de raw
-- @tparam number learn_wfd  fd du pipe learn
process_ipv6 = (raw, len, learn_wfd) ->
  return if len < NDP_MIN_LEN

  -- Vérifier IPv6 + ICMPv6 + type NDP
  next_header  = raw\byte 21
  icmpv6_type  = raw\byte 55

  return unless next_header == ICMPV6_PROTO
  return unless icmpv6_type == ICMPV6_TYPE_NS or icmpv6_type == ICMPV6_TYPE_NA

  -- Rejeter les Neighbor Solicitation de DAD (source = ::)
  -- et les sources multicast (commence par 0xff)
  src_first = raw\byte 23
  return if src_first == 0xff   -- multicast

  all_zero = true
  for i = 23, 38
    if raw\byte(i) ~= 0
      all_zero = false
      break
  return if all_zero   -- DAD (source non encore attribuée)

  -- Ignorer les MACs nulles
  mac_off = 7
  all_zero_mac = true
  for i = 0, 5
    if raw\byte(mac_off + i) ~= 0
      all_zero_mac = false
      break
  return if all_zero_mac

  msg = build_learn_msg raw, 23, 16, mac_off
  ok = write_learn learn_wfd, msg
  log_debug { action: "ndp_learned", mac: fmt_mac(raw, mac_off),
    ip: fmt_ipv6(raw, 23),
    type: icmpv6_type == ICMPV6_TYPE_NS and "NS" or "NA" } if ok

-- ── Boucle principale ─────────────────────────────────────────────

--- Démarre le worker ARP/NDP sniffer.
-- Écoute passivement les trames ARP et NDP sur l'interface bridge
-- et alimente le mac_learner via le pipe learn.
-- @tparam string ifname    Nom de l'interface bridge (ex : "br")
-- @tparam number learn_wfd fd d'écriture du pipe question→mac_learner
run = (ifname, learn_wfd) ->
  set_action_prefix "arp_"
  ifindex = tonumber C.if_nametoindex ifname
  if ifindex == 0
    errno = tonumber(ffi.C.__errno_location()[0])
    log_warn { action: "ifindex_failed", ifname: ifname, errno: errno }
    return

  arp_fd = open_socket ETH_P_ARP, ifindex
  unless arp_fd
    errno = tonumber(ffi.C.__errno_location()[0])
    log_warn { action: "socket_failed", proto: "ARP", ifname: ifname, errno: errno }
    return

  ip6_fd = open_socket ETH_P_IPV6, ifindex
  unless ip6_fd
    errno = tonumber(ffi.C.__errno_location()[0])
    log_warn { action: "socket_failed", proto: "IPv6", ifname: ifname, errno: errno }
    libc.close arp_fd
    return

  log_info { action: "start", ifname: ifname, ifindex: ifindex }

  -- poll sur les deux sockets
  pfds = ffi.new "struct pollfd[2]"
  pfds[0].fd     = arp_fd
  pfds[0].events = POLLIN
  pfds[1].fd     = ip6_fd
  pfds[1].events = POLLIN

  -- Buffer de réception partagé (MTU 1500 + Eth 14 + marge)
  buf     = ffi.new "uint8_t[2048]"
  buf_len = 2048

  bit = require "bit"

  while true
    C.poll pfds, 2, 5000

    if bit.band(pfds[0].revents, POLLIN) ~= 0
      n = C.recv arp_fd, buf, buf_len, 0
      if n >= ARP_MIN_LEN
        process_arp ffi.string(buf, n), n, learn_wfd

    if bit.band(pfds[1].revents, POLLIN) ~= 0
      n = C.recv ip6_fd, buf, buf_len, 0
      if n >= NDP_MIN_LEN
        process_ipv6 ffi.string(buf, n), n, learn_wfd

{ :run }
