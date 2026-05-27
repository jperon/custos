-- src/mac_prober.moon
-- Sondage actif IP→MAC via ARP request (IPv4) et Neighbor Solicitation (IPv6).
-- Utilisé par mac_learner quand une adresse est inconnue.
--
-- Fonctionnement :
--   1. init(ifname) : ouvre les sockets AF_PACKET, lit la MAC et l'IPv6
--      link-local du bridge depuis sysfs / /proc/net/if_inet6.
--      L'IPv4 n'est pas nécessaire : on envoie un ARP probe (SPA = 0.0.0.0,
--      RFC 5227) qui provoque quand même une ARP reply unicast.
--   2. probe_and_wait(ctx, ip_str, timeout_ms) : envoie ARP request ou NS,
--      poll jusqu'à la réponse ou le timeout, retourne la MAC ou nil.
--
-- Aucun thread, aucun coroutine : appel synchrone depuis handle_query.
-- Pas de dépendance à worker_arp_sniffer (qui fait l'apprentissage passif
-- en arrière-plan) ; les deux peuvent coexister sur la même interface.

{ :ffi, :libc } = require "ffi_defs"
{ :C, :AF_PACKET, :SOCK_RAW, :AF_INET6 } = require "lib.socket"
{ :log_debug, :log_warn } = require "log"
{ :ip2s } = require "ipparse.l3.ip"

bit = require "bit"

-- ── Constantes réseau ────────────────────────────────────────────

AF_PACKET  = 17
SOCK_RAW   = 3
POLLIN     = 1
AF_INET6   = 10
CLOCK_MONOTONIC = 1

-- Protocoles passés à socket(AF_PACKET, SOCK_RAW, proto) : network byte order.
ETH_P_ARP  = C.htons 0x0806
ETH_P_IPV6 = C.htons 0x86DD

ICMPV6_TYPE_NA = 136   -- Neighbor Advertisement

-- ── Temps monotone ───────────────────────────────────────────────

--- Retourne le temps monotone courant en millisecondes.
-- @treturn number  Millisecondes (entier)
get_ms = ->
  ts = ffi.new "timespec_t"
  libc.clock_gettime CLOCK_MONOTONIC, ts
  tonumber(ts.tv_sec) * 1000 + math.floor(tonumber(ts.tv_nsec) / 1000000)

-- ── Checksum ICMPv6 ──────────────────────────────────────────────

--- Accumule la somme de complément à 1 des octets d'une chaîne (mots 16 bits).
-- @tparam string s    Données
-- @tparam number acc  Accumulateur entrant
-- @treturn number Accumulateur mis à jour (non replié)
ones_add = (s, acc) ->
  i = 1
  n = #s
  while i <= n - 1
    acc += s\byte(i) * 256 + s\byte(i + 1)
    i += 2
  acc += s\byte(i) * 256 if i == n   -- octet impair, zero-padded
  acc

--- Replie une somme 32 bits en 16 bits et calcule le complément à 1.
-- @tparam number acc
-- @treturn number Checksum 16 bits
fold16 = (acc) ->
  while acc > 0xFFFF
    acc = bit.band(acc, 0xFFFF) + bit.rshift(acc, 16)
  bit.bxor acc, 0xFFFF

--- Calcule le checksum ICMPv6 (RFC 4443) sur pseudo-header IPv6 + payload.
-- Le payload doit avoir les 2 octets de checksum (positions 3-4) à zéro.
-- @tparam string src6    16 octets source IPv6
-- @tparam string dst6    16 octets destination IPv6
-- @tparam string payload Payload ICMPv6 (checksum zéro)
-- @treturn number Checksum 16 bits
icmpv6_cksum = (src6, dst6, payload) ->
  plen = #payload
  -- Pseudo-header : src(16) + dst(16) + upper_layer_length(4) + zeros(3) + next_header(1)
  pseudo = src6 .. dst6 ..
    string.char(
      bit.rshift(bit.band(plen, 0xFF000000), 24),
      bit.rshift(bit.band(plen, 0x00FF0000), 16),
      bit.rshift(bit.band(plen, 0x0000FF00), 8),
      bit.band(plen, 0xFF)
    ) ..
    "\x00\x00\x00\x3a"   -- 3 zéros + next_header = 58 (ICMPv6)
  fold16 ones_add payload, ones_add pseudo, 0

-- ── Conversion d'adresses ────────────────────────────────────────

--- Convertit une adresse IPv4 textuelle en 4 octets binaires.
-- @tparam string s  "a.b.c.d"
-- @treturn string|nil  4 octets ou nil si parse échoué
ip4_to_bin = (s) ->
  a, b, c, d = s\match "^(%d+)%.(%d+)%.(%d+)%.(%d+)$"
  return nil unless a
  string.char tonumber(a), tonumber(b), tonumber(c), tonumber(d)

--- Convertit une adresse IPv6 textuelle en 16 octets binaires via inet_pton.
-- @tparam string s  Adresse IPv6
-- @treturn string|nil  16 octets ou nil si parse échoué
ip6_to_bin = (s) ->
  buf = ffi.new "uint8_t[16]"
  return nil if C.inet_pton(AF_INET6, s, buf) ~= 1
  ffi.string buf, 16

--- Formate 6 octets (1-based) d'une chaîne en "aa:bb:cc:dd:ee:ff".
-- @tparam string s    Chaîne d'au moins off+5 octets
-- @tparam number off  Offset 1-based du premier octet
-- @treturn string
fmt_mac = (s, off) ->
  string.format "%02x:%02x:%02x:%02x:%02x:%02x",
    s\byte(off),   s\byte(off+1), s\byte(off+2),
    s\byte(off+3), s\byte(off+4), s\byte(off+5)

-- ── Lecture des informations du bridge ───────────────────────────

--- Lit la MAC du bridge depuis sysfs.
-- @tparam string ifname  Nom de l'interface (ex : "br")
-- @treturn string|nil  6 octets binaires ou nil
read_own_mac = (ifname) ->
  fh = io.open "/sys/class/net/#{ifname}/address", "r"
  return nil unless fh
  s = (fh\read "*a")\gsub "%s+", ""
  fh\close!
  a, b, c, d, e, f = s\match "^(%x+):(%x+):(%x+):(%x+):(%x+):(%x+)$"
  return nil unless a
  string.char(
    tonumber(a, 16), tonumber(b, 16), tonumber(c, 16),
    tonumber(d, 16), tonumber(e, 16), tonumber(f, 16)
  )

--- Lit l'adresse IPv6 link-local du bridge depuis /proc/net/if_inet6.
-- Scope 0x20 = link-local. Retourne nil si aucune trouvée.
-- @tparam string ifname  Nom de l'interface
-- @treturn string|nil  16 octets binaires ou nil
read_own_ip6 = (ifname) ->
  fh = io.open "/proc/net/if_inet6", "r"
  return nil unless fh
  result = nil
  for line in fh\lines!
    -- Format : hex_addr ifindex pfxlen scope flags ifname
    tok = {}
    for p in line\gmatch "%S+"
      tok[#tok + 1] = p
    -- tok[4] = scope (hex), tok[6] = interface name
    if #tok >= 6 and tok[6] == ifname and tok[4] == "20"
      hex = tok[1]
      bytes = ""
      for i = 1, 32, 2
        bytes = bytes .. string.char(tonumber(hex\sub(i, i + 1), 16))
      if #bytes == 16
        result = bytes
        break
  fh\close!
  result

-- ── Sockets AF_PACKET ────────────────────────────────────────────

--- Ouvre et lie un socket AF_PACKET/SOCK_RAW à une interface.
-- @tparam number  proto    Protocole Ethernet en network byte order (ex : ETH_P_ARP)
-- @tparam number  ifindex  Index de l'interface
-- @treturn number|nil  fd ou nil en cas d'erreur
open_socket = (proto, ifindex) ->
  fd = C.socket AF_PACKET, SOCK_RAW, proto
  return nil if fd < 0

  sll = ffi.new "struct sockaddr_ll"
  ffi.fill sll, ffi.sizeof(sll), 0
  sll.sll_family   = AF_PACKET
  sll.sll_protocol = proto
  sll.sll_ifindex  = ifindex

  if C.bind(fd, ffi.cast("struct sockaddr*", sll), ffi.sizeof(sll)) ~= 0
    libc.close fd
    return nil

  fd

-- ── Construction des paquets ─────────────────────────────────────

--- Construit une trame ARP request Ethernet+ARP (42 octets).
-- Utilise SPA = 0.0.0.0 (ARP probe RFC 5227) pour ne pas nécessiter
-- l'adresse IPv4 du bridge. La cible répond quand même avec une ARP reply
-- unicast vers notre MAC.
-- @tparam string our_mac   6 octets binaires (MAC du bridge)
-- @tparam string tgt4_bin  4 octets binaires (IPv4 cible)
-- @treturn string  Trame de 42 octets
build_arp_request = (our_mac, tgt4_bin) ->
  -- Ethernet header (14 octets)
  eth = "\xff\xff\xff\xff\xff\xff" ..   -- dst : broadcast
    our_mac ..                           -- src
    "\x08\x06"                           -- EtherType ARP

  -- ARP IPv4 request (28 octets)
  arp = "\x00\x01" ..             -- ar_hrd = 1 (Ethernet)
    "\x08\x00" ..                  -- ar_pro = 0x0800 (IPv4)
    "\x06" ..                      -- ar_hln = 6
    "\x04" ..                      -- ar_pln = 4
    "\x00\x01" ..                  -- ar_op = 1 (request)
    our_mac ..                     -- SHA : sender hardware addr
    "\x00\x00\x00\x00" ..          -- SPA = 0.0.0.0 (ARP probe)
    "\x00\x00\x00\x00\x00\x00" ..  -- THA : zéros
    tgt4_bin                       -- TPA : cible

  eth .. arp

--- Construit une trame Ethernet+IPv6+ICMPv6 Neighbor Solicitation.
-- Destination multicast : ff02::1:ffXX:XXXX (solicited-node de la cible).
-- Checksum ICMPv6 calculé selon RFC 4443.
-- @tparam string our_mac   6 octets binaires (MAC du bridge)
-- @tparam string our_ip6   16 octets binaires (IPv6 link-local du bridge)
-- @tparam string tgt6_bin  16 octets binaires (IPv6 cible)
-- @treturn string  Trame de 86 octets
build_ns_frame = (our_mac, our_ip6, tgt6_bin) ->
  -- Adresse multicast solicited-node : ff02::1:ff + 3 derniers octets de la cible
  -- ff02:0000:0000:0000:0000:0001:ffXX:XXXX (16 octets)
  sol = "\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff" ..
    tgt6_bin\sub 14, 16   -- derniers 3 octets

  -- MAC multicast Ethernet : 33:33:ff + 3 derniers octets
  eth_dst = "\x33\x33\xff" .. tgt6_bin\sub 14, 16

  -- Payload ICMPv6 NS (32 octets) avec checksum = 0 pour le calcul
  -- type(1) code(1) cksum(2) reserved(4) target(16) SLLA-opt(8)
  ns_body = string.char(135, 0, 0, 0) ..   -- type=NS, code=0, cksum=0
    "\x00\x00\x00\x00" ..                   -- reserved
    tgt6_bin ..                             -- target (16 octets)
    string.char(1, 1) .. our_mac            -- option SLLA : type=1, len=1, mac

  -- IPv6 header (40 octets)
  ns_len = #ns_body   -- 32
  ip6_hdr = "\x60\x00\x00\x00" ..           -- version=6, TC=0, flow=0
    string.char(0, ns_len) ..               -- payload_length (2 octets BE)
    "\x3a\xff" ..                           -- next_header=ICMPv6 (58), hop_limit=255
    our_ip6 ..                              -- source (16 octets)
    sol                                     -- destination (16 octets)

  -- Calcul du checksum ICMPv6 et insertion aux octets 3-4 du payload
  ck = icmpv6_cksum our_ip6, sol, ns_body
  ns_body = ns_body\sub(1, 2) ..
    string.char(bit.rshift(ck, 8), bit.band(ck, 0xFF)) ..
    ns_body\sub 5

  -- Ethernet header (14 octets)
  eth_hdr = eth_dst .. our_mac .. "\x86\xDD"

  eth_hdr .. ip6_hdr .. ns_body

-- ── Envoi ────────────────────────────────────────────────────────

--- Envoie une trame Ethernet brute via AF_PACKET sur l'interface spécifiée.
-- @tparam number  fd       fd du socket AF_PACKET
-- @tparam number  ifindex  Index de l'interface
-- @tparam string  frame    Trame complète (à partir de l'en-tête Ethernet)
-- @treturn boolean  true si tous les octets ont été envoyés
send_frame = (fd, ifindex, frame) ->
  sll = ffi.new "struct sockaddr_ll"
  ffi.fill sll, ffi.sizeof(sll), 0
  sll.sll_family  = AF_PACKET
  sll.sll_ifindex = ifindex
  n = C.sendto fd, frame, #frame, 0,
    ffi.cast("const struct sockaddr*", sll), ffi.sizeof(sll)
  n == #frame

-- ── Parsing des réponses ─────────────────────────────────────────

--- Analyse une trame ARP reçue et retourne (ip4_str, mac_str) si c'est
-- une ARP reply dont le SPA correspond à l'adresse cible sondée.
--
-- Offsets 1-based :
--   7-12  Ethernet src = MAC du répondant
--   21-22 ar_op = 2 (reply)
--   23-28 SHA (sender hardware addr)
--   29-32 SPA (sender protocol addr) = IPv4 du répondant
--
-- @tparam string raw       Trame brute
-- @tparam number len       Longueur utilisable
-- @tparam string tgt4_bin  4 octets de l'IPv4 attendue (filtrage)
-- @treturn string|nil, string|nil  ip4_str, mac_str ou nil, nil
parse_arp_reply = (raw, len, tgt4_bin) ->
  return nil, nil if len < 42

  hw_type    = raw\byte(15) * 256 + raw\byte(16)
  proto_type = raw\byte(17) * 256 + raw\byte(18)
  hw_len     = raw\byte(19)
  proto_len  = raw\byte(20)
  op         = raw\byte(21) * 256 + raw\byte(22)

  return nil, nil unless hw_type == 1 and proto_type == 0x0800
  return nil, nil unless hw_len == 6 and proto_len == 4
  return nil, nil unless op == 2   -- reply seulement

  -- Filtrer par SPA = adresse sondée
  spa = raw\sub 29, 32
  return nil, nil unless spa == tgt4_bin

  ip4_str = "#{raw\byte 29}.#{raw\byte 30}.#{raw\byte 31}.#{raw\byte 32}"
  mac_str = fmt_mac raw, 23   -- SHA
  ip4_str, mac_str

--- Analyse une trame IPv6 reçue et retourne (ip6_str, mac_str) si c'est
-- un Neighbor Advertisement dont le target correspond à l'adresse sondée.
--
-- Offsets 1-based :
--   7-12  Ethernet src = MAC du répondant
--   21    IPv6 next_header (doit être 58 = ICMPv6)
--   23-38 IPv6 source
--   55    ICMPv6 type (doit être 136 = NA)
--   63-78 NA target = IPv6 sondée
--
-- @tparam string raw       Trame brute
-- @tparam number len       Longueur utilisable
-- @tparam string tgt6_bin  16 octets de l'IPv6 attendue (filtrage)
-- @treturn string|nil, string|nil  ip6_str, mac_str ou nil, nil
parse_na_reply = (raw, len, tgt6_bin) ->
  return nil, nil if len < 86   -- 14 Eth + 40 IPv6 + 8 NA-fixe + 16 target + 8 TLLA

  next_hdr    = raw\byte 21
  icmpv6_type = raw\byte 55

  return nil, nil unless next_hdr == 58           -- ICMPv6
  return nil, nil unless icmpv6_type == ICMPV6_TYPE_NA

  -- Filtrer par NA target = adresse sondée
  na_target = raw\sub 63, 78
  return nil, nil unless na_target == tgt6_bin

  -- MAC source Ethernet (bytes 7-12)
  mac_str = fmt_mac raw, 7

  -- IPv6 source via ip2s pour cohérence avec le reste du codebase
  ip6_src = ip2s raw\sub 23, 38
  return nil, nil unless ip6_src

  ip6_src, mac_str

-- ── Boucle de réception ──────────────────────────────────────────

--- Poll sur un socket jusqu'à recevoir un paquet satisfaisant parse_fn,
-- ou jusqu'à l'expiration du timeout.
-- @tparam number   fd          fd du socket AF_PACKET
-- @tparam number   timeout_ms  Délai maximum en ms
-- @tparam function parse_fn    Appelée avec (raw, n) → mac_str|nil
-- @treturn string|nil  MAC ou nil si timeout
wait_reply = (fd, timeout_ms, parse_fn) ->
  pfd = ffi.new "struct pollfd[1]"
  pfd[0].fd     = fd
  pfd[0].events = POLLIN
  buf       = ffi.new "uint8_t[2048]"
  start_ms  = get_ms!

  while true
    remaining = timeout_ms - (get_ms! - start_ms)
    break if remaining <= 0
    rc = C.poll pfd, 1, remaining
    break if rc <= 0   -- 0 = timeout, <0 = erreur

    if bit.band(pfd[0].revents, POLLIN) ~= 0
      n = C.recv fd, buf, 2048, 0
      if n > 0
        raw = ffi.string buf, n
        mac = parse_fn raw, n
        return mac if mac

  nil

-- ── API publique ─────────────────────────────────────────────────

--- Initialise le sondeur MAC actif pour l'interface bridge spécifiée.
-- Lit la MAC et l'IPv6 link-local du bridge, ouvre les sockets AF_PACKET.
-- Si l'IPv6 link-local n'est pas trouvée, les sondes NS sont désactivées
-- (get_mac tombera en "unknown" pour les adresses IPv6 non-EUI-64).
-- @tparam string ifname  Nom de l'interface bridge (ex : "br")
-- @treturn table|nil  Contexte de sondage, ou nil si initialisation échouée
init = (ifname) ->
  our_mac = read_own_mac ifname
  unless our_mac
    log_warn -> { action: "mac_prober_no_mac", ifname: ifname }
    return nil

  ifindex = tonumber C.if_nametoindex ifname
  if ifindex == 0
    errno = tonumber(ffi.C.__errno_location()[0])
    log_warn -> { action: "mac_prober_no_ifindex", ifname: ifname, errno: errno }
    return nil

  arp_fd = open_socket ETH_P_ARP, ifindex
  unless arp_fd
    errno = tonumber(ffi.C.__errno_location()[0])
    log_warn -> { action: "mac_prober_arp_socket_failed", ifname: ifname, errno: errno }
    return nil

  our_ip6 = read_own_ip6 ifname
  ip6_fd  = nil

  if our_ip6
    ip6_fd = open_socket ETH_P_IPV6, ifindex
    unless ip6_fd
      errno = tonumber(ffi.C.__errno_location()[0])
      log_warn -> { action: "mac_prober_ip6_socket_failed", ifname: ifname, errno: errno,
        msg: "NS probes disabled" }
  else
    log_warn -> { action: "mac_prober_no_ip6", ifname: ifname,
      msg: "no link-local found, NS probes disabled" }

  { :ifname, :ifindex, :our_mac, :our_ip6, :arp_fd, :ip6_fd }

--- Sonde activement une adresse IP et attend la réponse (synchrone).
-- Envoie un ARP request (IPv4) ou un Neighbor Solicitation (IPv6),
-- puis poll jusqu'à recevoir la réponse ou l'expiration du timeout.
-- Retourne nil immédiatement si le protocole n'est pas disponible
-- (socket non ouvert, pas d'adresse source IPv6, etc.).
-- @tparam table  ctx         Contexte retourné par init()
-- @tparam string ip_str      Adresse IP cible (IPv4 ou IPv6)
-- @tparam number timeout_ms  Délai maximum en ms (défaut : 200)
-- @treturn string|nil  MAC "aa:bb:cc:dd:ee:ff" ou nil si pas de réponse
probe_and_wait = (ctx, ip_str, timeout_ms) ->
  return nil unless ctx
  timeout_ms = timeout_ms or 200

  is_ipv6 = ip_str\find(":", 1, true) ~= nil

  if is_ipv6
    return nil unless ctx.ip6_fd and ctx.our_ip6

    tgt_bin = ip6_to_bin ip_str
    return nil unless tgt_bin

    frame = build_ns_frame ctx.our_mac, ctx.our_ip6, tgt_bin
    return nil unless frame

    unless send_frame ctx.ip6_fd, ctx.ifindex, frame
      log_warn -> { action: "mac_prober_ns_send_failed", ip: ip_str }
      return nil

    log_debug -> { action: "mac_prober_ns_sent", ip: ip_str }

    return wait_reply ctx.ip6_fd, timeout_ms, (raw, n) ->
      _, mac = parse_na_reply raw, n, tgt_bin
      mac

  else
    tgt_bin = ip4_to_bin ip_str
    return nil unless tgt_bin

    frame = build_arp_request ctx.our_mac, tgt_bin

    unless send_frame ctx.arp_fd, ctx.ifindex, frame
      log_warn -> { action: "mac_prober_arp_send_failed", ip: ip_str }
      return nil

    log_debug -> { action: "mac_prober_arp_sent", ip: ip_str }

    return wait_reply ctx.arp_fd, timeout_ms, (raw, n) ->
      _, mac = parse_arp_reply raw, n, tgt_bin
      mac

--- Envoie une sonde ARP request ou NS ICMPv6 pour l'adresse spécifiée.
-- Non-bloquant : retourne immédiatement après l'envoi.
-- La réponse arrivera sur ctx.arp_fd (IPv4) ou ctx.ip6_fd (IPv6).
-- @tparam table  ctx     Contexte retourné par init()
-- @tparam string ip_str  Adresse IP cible
-- @treturn boolean  true si la sonde a été envoyée avec succès
send_probe = (ctx, ip_str) ->
  return false unless ctx
  is_ipv6 = ip_str\find(":", 1, true) ~= nil

  if is_ipv6
    return false unless ctx.ip6_fd and ctx.our_ip6
    tgt_bin = ip6_to_bin ip_str
    return false unless tgt_bin
    frame = build_ns_frame ctx.our_mac, ctx.our_ip6, tgt_bin
    return false unless frame
    send_frame ctx.ip6_fd, ctx.ifindex, frame
  else
    tgt_bin = ip4_to_bin ip_str
    return false unless tgt_bin
    frame = build_arp_request ctx.our_mac, tgt_bin
    send_frame ctx.arp_fd, ctx.ifindex, frame

--- Parse une trame reçue sur arp_fd comme ARP reply (sans filtrage par cible).
-- Retourne (ip_str, mac_str) pour toute ARP reply valide à MAC non nulle.
-- Retourne nil, nil pour un ARP request ou toute trame mal formée.
-- @tparam string raw  Trame brute
-- @tparam number n    Longueur
-- @treturn string|nil, string|nil  IPv4 du répondant, MAC du répondant
parse_arp_frame = (raw, n) ->
  return nil, nil if n < 42
  hw_type    = raw\byte(15) * 256 + raw\byte(16)
  proto_type = raw\byte(17) * 256 + raw\byte(18)
  hw_len     = raw\byte(19)
  proto_len  = raw\byte(20)
  op         = raw\byte(21) * 256 + raw\byte(22)
  return nil, nil unless hw_type == 1 and proto_type == 0x0800
  return nil, nil unless hw_len == 6 and proto_len == 4
  return nil, nil unless op == 2
  -- Ignorer les MACs nulles
  all_zero = true
  for i = 23, 28
    if raw\byte(i) ~= 0
      all_zero = false
      break
  return nil, nil if all_zero
  ip_str  = "#{raw\byte 29}.#{raw\byte 30}.#{raw\byte 31}.#{raw\byte 32}"
  mac_str = fmt_mac raw, 23
  ip_str, mac_str

--- Parse une trame reçue sur ip6_fd comme Neighbor Advertisement (sans filtrage).
-- ip_str est l'adresse du NA target (l'IP sondée).
-- mac_str est la MAC source Ethernet du répondant.
-- @tparam string raw  Trame brute
-- @tparam number n    Longueur
-- @treturn string|nil, string|nil  IPv6 du NA target, MAC du répondant
parse_na_frame = (raw, n) ->
  return nil, nil if n < 78   -- 14 Eth + 40 IPv6 + 24 NA (sans options)
  return nil, nil unless raw\byte(21) == 58            -- ICMPv6
  return nil, nil unless raw\byte(55) == ICMPV6_TYPE_NA
  -- Ignorer les MACs nulles
  all_zero = true
  for i = 7, 12
    if raw\byte(i) ~= 0
      all_zero = false
      break
  return nil, nil if all_zero
  -- NA target : bytes 63-78 → ip2s pour cohérence avec le reste du codebase
  na_target_ip = ip2s raw\sub 63, 78
  return nil, nil unless na_target_ip
  na_target_ip, fmt_mac(raw, 7)

{ :init, :probe_and_wait, :send_probe, :parse_arp_frame, :parse_na_frame, :get_ms }
