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
{ :C, :AF_PACKET, :SOCK_RAW } = require "lib.socket"
{ :log_info, :log_warn, :log_debug, :set_action_prefix } = require "log"
{ :ip2s } = require "ipparse.l3.ip"

-- ── Constantes réseau ────────────────────────────────────────────

POLLIN     = 1

-- htons() pour les protocoles passés à socket() :
-- AF_PACKET reçoit le protocole en network byte order.
ETH_P_ALL  = C.htons 0x0003   -- Tous les protocoles (pour capturer les paquets sortants)

-- Socket options pour AF_PACKET (packet_mreq)
SOL_PACKET              = 263
PACKET_ADD_MEMBERSHIP   = 1
PACKET_MR_PROMISC       = 1

-- Filtre BPF noyau (SO_ATTACH_FILTER) : ne laisse remonter en userspace
-- que les trames pertinentes (ARP, ou IPv6/ICMPv6 NS/NA), pour éviter de
-- réveiller le worker — et d'allouer une string Lua — sur chaque paquet du
-- plan de données (IPv4/TCP/UDP) quand le lien est chargé.
SOL_SOCKET_C            = 1
SO_ATTACH_FILTER        = 26

-- ICMPv6 next-header number et types NDP
ICMPV6_PROTO        = 58
ICMPV6_TYPE_NS      = 135   -- Neighbor Solicitation
ICMPV6_TYPE_NA      = 136   -- Neighbor Advertisement

-- Options NDP (RFC 4861 section 4.6)
NDP_OPT_TGT_LLA      = 2    -- Target Link-Layer Address

-- Taille minimale des trames attendues (octets, base 1 Lua)
ARP_MIN_LEN  = 42    -- 14 (Eth) + 28 (ARP IPv4/Ethernet)
NDP_MIN_LEN  = 56    -- 14 (Eth) + 40 (IPv6) + 2 (ICMPv6 type+code)
NDP_OPT_MIN_LEN = 8  -- Taille minimale pour une option (Type + Length + au moins 6 octets de MAC)

-- ── Helpers ──────────────────────────────────────────────────────

{ mac2s: fmt_mac } = require "packet_utils"

--- Formate 16 octets d'une chaîne Lua en adresse IPv6 textuelle (pour les logs).
-- Utilise ip2s pour garantir la cohérence avec le reste du codebase.
-- @tparam string s  Chaîne d'au moins o+15 octets
-- @tparam number o  Offset 1-based du premier octet dans s
-- @treturn string Adresse IPv6
fmt_ipv6 = (s, o) ->
  ip2s s\sub o, o + 15

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

--- Extrait l'option TLLA (Target Link-Layer Address) d'un message NDP.
-- Les options NDP commencent après l'en-tête ICMPv6 fixe (24 octets pour NS/NA).
-- Format option : Type(1) + Length(1, unités de 8 octets) + Data
-- @tparam string raw       Trame brute complète
-- @tparam number opt_start  Offset 1-based du début des options (après Target Address)
-- @tparam number len       Longueur totale de la trame
-- @treturn string|nil  6 octets de la MAC si trouvée, nil sinon
extract_tlla = (raw, opt_start, len) ->
  return nil if len < opt_start + NDP_OPT_MIN_LEN

  offset = opt_start
  while offset + 2 <= len
    opt_type = raw\byte offset
    opt_len  = raw\byte(offset + 1) * 8  -- Length est en unités de 8 octets

    return nil if opt_len < 2 or opt_len > 255  -- Option invalide
    return nil if offset + opt_len > len  -- Option tronquée

    if opt_type == NDP_OPT_TGT_LLA
      -- Vérifier qu'il y a au moins 6 octets de données (après Type + Length)
      if opt_len >= 8  -- 2 octets header + 6 octets MAC minimum
        mac_start = offset + 2
        -- Vérifier que la MAC n'est pas nulle
        all_zero = true
        for i = 0, 5
          if raw\byte(mac_start + i) ~= 0
            all_zero = false
            break
        return raw\sub(mac_start, mac_start + 5) unless all_zero

    offset += opt_len

  nil

-- ── Filtre BPF ───────────────────────────────────────────────────

-- Programme cBPF équivalent à `arp or (ip6 and icmp6 and (type 135 or 136))`.
-- Reproduit exactement les tests faits ensuite en Lua (EtherType, next-header
-- ICMPv6 à l'offset 20, type ICMPv6 à l'offset 54), si bien que le noyau écarte
-- tout le reste avant qu'il n'atteigne recv().
--   BPF_LD|H|ABS = 0x28, BPF_LD|B|ABS = 0x30,
--   BPF_JMP|JEQ|K = 0x15, BPF_RET|K = 0x06
BPF_PROG = {
  { 0x28, 0, 0, 12 }       -- ldh  [12]            ; EtherType
  { 0x15, 7, 0, 0x0806 }   -- jeq  0x0806 -> accept ; ARP
  { 0x15, 0, 5, 0x86DD }   -- jne  0x86DD -> drop   ; sinon ce doit être IPv6
  { 0x30, 0, 0, 20 }       -- ldb  [20]            ; IPv6 next header
  { 0x15, 0, 3, 58 }       -- jne  58     -> drop   ; ICMPv6 ?
  { 0x30, 0, 0, 54 }       -- ldb  [54]            ; type ICMPv6
  { 0x15, 2, 0, 135 }      -- jeq  135    -> accept ; Neighbor Solicitation
  { 0x15, 1, 0, 136 }      -- jeq  136    -> accept ; Neighbor Advertisement
  { 0x06, 0, 0, 0 }        -- ret  0                ; drop
  { 0x06, 0, 0, 0xFFFF }   -- ret  0xFFFF           ; accept
}

--- Attache le filtre BPF NDP/ARP au socket via SO_ATTACH_FILTER.
-- Best-effort : un échec laisse le socket fonctionnel (filtrage userspace seul).
-- @tparam number fd  fd du socket AF_PACKET
attach_filter = (fd) ->
  prog = ffi.new "struct sock_filter[?]", #BPF_PROG
  for i, ins in ipairs BPF_PROG
    prog[i - 1].code = ins[1]
    prog[i - 1].jt   = ins[2]
    prog[i - 1].jf   = ins[3]
    prog[i - 1].k    = ins[4]

  fprog = ffi.new "struct sock_fprog"
  fprog.len    = #BPF_PROG
  fprog.filter = prog

  if C.setsockopt(fd, SOL_SOCKET_C, SO_ATTACH_FILTER, fprog, ffi.sizeof(fprog)) ~= 0
    log_debug -> { action: "bpf_attach_failed", errno: tonumber(ffi.C.__errno_location()[0]) }
    false
  else
    true

-- ── Sockets AF_PACKET ────────────────────────────────────────────

--- Ouvre et lie un socket AF_PACKET/SOCK_RAW à une interface avec ETH_P_ALL.
-- Utilise ETH_P_ALL pour capturer tous les protocoles, y compris les paquets sortants.
-- Le filtrage de protocole se fait en userspace.
-- @tparam number  ifindex    Index de l'interface (résultat de if_nametoindex)
-- @treturn number|nil  fd du socket, ou nil en cas d'erreur
open_socket = (ifindex) ->
  fd = C.socket AF_PACKET, SOCK_RAW, ETH_P_ALL
  if fd < 0
    return nil

  sll = ffi.new "struct sockaddr_ll"
  ffi.fill sll, ffi.sizeof(sll), 0
  sll.sll_family   = AF_PACKET
  sll.sll_protocol = ETH_P_ALL
  sll.sll_ifindex  = ifindex

  if C.bind(fd, ffi.cast("struct sockaddr*", sll), ffi.sizeof(sll)) ~= 0
    libc.close fd
    return nil

  -- Filtre BPF noyau : n'éveille le worker que pour ARP/NDP, pas pour tout
  -- le plan de données. Indispensable pour la tenue en charge.
  attach_filter fd

  -- Activer le mode promiscuous pour capturer les paquets sortants
  mreq = ffi.new "struct packet_mreq"
  ffi.fill mreq, ffi.sizeof(mreq), 0
  mreq.mr_ifindex = ifindex
  mreq.mr_type    = PACKET_MR_PROMISC
  mreq.mr_alen    = 0

  if C.setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq, ffi.sizeof(mreq)) ~= 0
    -- Le mode promiscuous peut échouer (permissions, interface non bridge, etc.)
    -- On continue quand même, on captura seulement les paquets entrants
    log_debug -> { action: "promisc_failed", ifindex: ifindex, errno: tonumber(ffi.C.__errno_location()[0]) }

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
  log_debug -> { action: "arp_learned", mac: fmt_mac(raw, mac_off),
    ip: "#{raw\byte 29}.#{raw\byte 30}.#{raw\byte 31}.#{raw\byte 32}" } if ok

--- Traite une trame IPv6 et écrit l'association IPv6→MAC dans le pipe
-- si c'est un NDP Neighbor Solicitation (135) ou Advertisement (136).
--
-- Conformément à RFC 4861 :
--   • NS (135) : utilise IPv6 source + MAC source Ethernet
--   • NA (136) : utilise Target Address + option TLLA (Target Link-Layer Address)
--               ou MAC source Ethernet en fallback si TLLA absent
--
-- Structure de la trame (offset 1-based Lua, EtherType 0x86DD filtré) :
--   1-6   Ethernet dst MAC
--   7-12  Ethernet src MAC
--   13-14 EtherType (0x86DD)
--   ── IPv6 header (40 octets) ──────────────────────────────────
--   15-20 version / TC / flow label / payload length
--   21    next header       (doit être 58 = ICMPv6)
--   22    hop limit
--   23-38 source IPv6
--   39-54 destination IPv6
--   ── ICMPv6 ───────────────────────────────────────────────────
--   55    ICMPv6 type       (135 = NS, 136 = NA)
--   56-58 ICMPv6 code + checksum
--   59-62 ICMPv6 reserved/flags
--   63-78 Target Address   ← Important pour NA (adresse annoncée)
--   79+   Options NDP     ← TLLA (type 2) pour NA
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

  -- Ignorer les MACs nulles (source Ethernet)
  mac_src_off = 7
  all_zero_mac = true
  for i = 0, 5
    if raw\byte(mac_src_off + i) ~= 0
      all_zero_mac = false
      break
  return if all_zero_mac

  if icmpv6_type == ICMPV6_TYPE_NS
    -- ── Neighbor Solicitation (RFC 4861 section 4.3) ──
    -- Utiliser IPv6 source + MAC source Ethernet
    -- Rejeter DAD (source = ::) et sources multicast

    src_first = raw\byte 23
    return if src_first == 0xff   -- multicast

    all_zero = true
    for i = 23, 38
      if raw\byte(i) ~= 0
        all_zero = false
        break
    return if all_zero   -- DAD (source non encore attribuée)

    msg = build_learn_msg raw, 23, 16, mac_src_off
    ok = write_learn learn_wfd, msg
    log_debug -> { action: "ndp_learned", mac: fmt_mac(raw, mac_src_off),
      ip: fmt_ipv6(raw, 23), type: "NS" } if ok

  else
    -- ── Neighbor Advertisement (RFC 4861 section 4.4) ──
    -- Utiliser Target Address (bytes 63-78) + option TLLA (type 2)
    -- ou MAC source Ethernet en fallback si TLLA absent
    -- NA peut avoir Source Address = :: (gratuitous NA), ne pas filtrer

    -- Vérifier que la trame contient au moins le Target Address (78 octets)
    return if len < 78

    -- Target Address : bytes 63-78
    target_off = 63
    -- Vérifier que Target Address n'est pas multicast (commence par 0xff)
    target_first = raw\byte target_off
    return if target_first == 0xff

    -- Rechercher l'option TLLA (Target Link-Layer Address, type 2)
    -- Options commencent après Target Address (byte 79)
    tlla_mac = extract_tlla raw, 79, len

    if tlla_mac
      -- Utiliser la MAC de l'option TLLA
      -- Construire le message manuellement car tlla_mac est déjà extrait
      msg = ffi.new "uint8_t[22]"
      -- Target Address (16 octets)
      for i = 0, 15
        msg[i] = raw\byte(target_off + i)
      -- MAC TLLA (6 octets)
      for i = 0, 5
        msg[16 + i] = tlla_mac\byte(i + 1)

      ok = write_learn learn_wfd, msg
      log_debug -> { action: "ndp_learned",
        mac: fmt_mac(tlla_mac, 1),
        ip: fmt_ipv6(raw, target_off),
        type: "NA",
        tlla: true } if ok
    else
      -- Fallback : utiliser MAC source Ethernet
      msg = build_learn_msg raw, target_off, 16, mac_src_off
      ok = write_learn learn_wfd, msg
      log_debug -> { action: "ndp_learned",
        mac: fmt_mac(raw, mac_src_off),
        ip: fmt_ipv6(raw, target_off),
        type: "NA",
        tlla: false } if ok

-- ── Boucle principale ─────────────────────────────────────────────

--- Démarre le worker ARP/NDP sniffer.
-- Écoute passivement les trames ARP et NDP sur les interfaces bridge slaves.
-- Utilise ETH_P_ALL pour capturer tous les protocoles, y compris les paquets sortants.
-- Le filtrage de protocole se fait en userspace.
-- @tparam table ifnames   Tableau de noms d'interfaces (bridge slaves ou bridge)
-- @tparam number learn_wfd fd d'écriture du pipe question→mac_learner
run = (ifnames, learn_wfd) ->
  set_action_prefix "arp_"

  -- Normaliser ifnames en tableau
  if type(ifnames) == "string"
    ifnames = { ifnames }

  -- Ouvrir un socket par interface avec ETH_P_ALL
  fds = {}

  for ifname in *ifnames
    ifindex = tonumber C.if_nametoindex ifname
    if ifindex == 0
      errno = tonumber(ffi.C.__errno_location()[0])
      log_warn -> { action: "ifindex_failed", ifname: ifname, errno: errno }
      continue

    fd = open_socket ifindex
    if fd
      table.insert fds, fd
      log_debug -> { action: "socket_open", ifname: ifname, ifindex: ifindex }
    else
      errno = tonumber(ffi.C.__errno_location()[0])
      log_warn -> { action: "socket_failed", ifname: ifname, errno: errno }

  if #fds == 0
    log_warn -> { action: "no_sockets", interfaces: table.concat(ifnames, ",") }
    return

  log_info -> { action: "start", interfaces: table.concat(ifnames, ","), sockets: #fds }

  -- poll sur tous les sockets
  pfds = ffi.new "struct pollfd[?]", #fds
  for i, fd in ipairs fds
    pfds[i].fd = fd
    pfds[i].events = POLLIN

  -- Buffer de réception partagé (MTU 1500 + Eth 14 + marge)
  buf     = ffi.new "uint8_t[2048]"
  buf_len = 2048

  bit = require "bit"

  while true
    C.poll pfds, #fds, 5000

    for i = 0, #fds - 1
      if bit.band(pfds[i].revents, POLLIN) ~= 0
        fd = pfds[i].fd
        n = C.recv fd, buf, buf_len, 0
        if n > 14  -- Au moins un header Ethernet
          raw = ffi.string buf, n
          -- Filtrer par EtherType (bytes 13-14 en network byte order)
          ethertype = raw\byte(13) * 256 + raw\byte(14)

          if ethertype == 0x0806 and n >= ARP_MIN_LEN
            process_arp raw, n, learn_wfd
          elseif ethertype == 0x86DD and n >= NDP_MIN_LEN
            process_ipv6 raw, n, learn_wfd

-- BPF_PROG est exporté pour permettre la validation du programme cBPF
-- par les tests unitaires (interpréteur cBPF, sans socket réel).
{ :run, :BPF_PROG }
