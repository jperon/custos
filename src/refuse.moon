-- src/refuse.moon
-- Envoi de réponses DNS REFUSED (RCODE 5 + EDE Filtered) aux clients bloqués.
--
-- Stratégie : crée un socket UDP par réponse avec IP_TRANSPARENT pour pouvoir
-- binder à l'IP du résolveur DNS (pkt.ip.dst_ip_raw), même si cette IP
-- n'appartient pas à l'interface locale.  Cela garantit que le REFUSED arrive
-- avec la bonne IP source (celle du résolveur interrogé), que le filtre soit en
-- mode bridge, routeur ou Docker FORWARD.
--
-- Pré-requis : CAP_NET_ADMIN (présent en Docker privilégié et sur la VM filtre).

{ :ffi, :libc } = require "ffi_defs"
{ :AF_INET, :AF_INET6 } = require "config"
{ :log_warn, :log_info } = require "log"

-- ── Constantes POSIX ─────────────────────────────────────────────
SOCK_DGRAM      = 2
SOL_SOCKET      = 1
SO_REUSEADDR    = 2
SO_REUSEPORT    = 15    -- Linux (x86/arm64/riscv)
IPPROTO_IP      = 0
IPPROTO_IPV6    = 41
IP_TRANSPARENT  = 19    -- Linux
IPV6_TRANSPARENT = 75   -- Linux

-- ── Vérifie la disponibilité de CAP_NET_ADMIN au démarrage ───────
admin_available = false  -- sera mis à true par init()

-- ── API publique ─────────────────────────────────────────────────

--- Vérifie que IP_TRANSPARENT est utilisable (CAP_NET_ADMIN requis).
-- À appeler une seule fois après fork(), avant le traitement des paquets.
-- @treturn nil
init = ->
  -- Tente d'ouvrir un socket IP_TRANSPARENT de test pour valider les droits.
  fd = libc.socket AF_INET, SOCK_DGRAM, 0
  if fd >= 0
    one = ffi.new "int[1]", 1
    rc = libc.setsockopt fd, IPPROTO_IP, IP_TRANSPARENT, one, ffi.sizeof "int"
    libc.close fd
    if rc == 0
      admin_available = true
      log_info { action: "refuse_ready", mode: "ip_transparent" }
    else
      log_warn { action: "refuse_init_fail",
                 err: "IP_TRANSPARENT non disponible (CAP_NET_ADMIN requis)" }
  else
    log_warn { action: "refuse_init_fail", err: "socket() echec" }

--- Envoie un payload DNS REFUSED vers le client, en spoofant l'IP source du résolveur.
-- Crée un socket éphémère bindé avec IP_TRANSPARENT à src_ip_raw:53.
-- @tparam string dst_ip_raw  4 ou 16 octets (IP du client — src de la question)
-- @tparam number dst_port    Port source de la question originale
-- @tparam string dns_payload Payload DNS REFUSED
-- @tparam number af          AF_INET (2) ou AF_INET6 (10)
-- @tparam string src_ip_raw  4 ou 16 octets (IP du résolveur — dst de la question)
-- @treturn nil
send_refused = (dst_ip_raw, dst_port, dns_payload, af, src_ip_raw) ->
  return unless admin_available

  fd = libc.socket af, SOCK_DGRAM, 0
  return if fd < 0

  one = ffi.new "int[1]", 1
  libc.setsockopt fd, SOL_SOCKET, SO_REUSEADDR, one, ffi.sizeof "int"
  libc.setsockopt fd, SOL_SOCKET, SO_REUSEPORT, one, ffi.sizeof "int"

  if af == AF_INET
    libc.setsockopt fd, IPPROTO_IP, IP_TRANSPARENT, one, ffi.sizeof "int"
    -- Bind à src_ip_raw:53 (IP du résolveur interrogé par le client)
    src = ffi.new "struct sockaddr_in"
    src.sin_family = AF_INET
    src.sin_port   = libc.htons 53
    ffi.copy src.sin_addr, src_ip_raw, 4
    rc = libc.bind fd, ffi.cast("struct sockaddr*", src), ffi.sizeof "struct sockaddr_in"
    if rc < 0
      libc.close fd
      log_warn { action: "refuse_bind_fail", af: "ipv4", err: ffi.errno! }
      return
    dst = ffi.new "struct sockaddr_in"
    dst.sin_family = AF_INET
    dst.sin_port   = libc.htons dst_port
    ffi.copy dst.sin_addr, dst_ip_raw, 4
    rc = libc.sendto fd, dns_payload, #dns_payload, 0,
      ffi.cast("struct sockaddr*", dst), ffi.sizeof "struct sockaddr_in"
    log_warn { action: "sendto_failed", af: "ipv4", err: ffi.errno! } if rc < 0
  else
    libc.setsockopt fd, IPPROTO_IPV6, IPV6_TRANSPARENT, one, ffi.sizeof "int"
    src = ffi.new "struct sockaddr_in6"
    src.sin6_family = AF_INET6
    src.sin6_port   = libc.htons 53
    ffi.copy src.sin6_addr, src_ip_raw, 16
    rc = libc.bind fd, ffi.cast("struct sockaddr*", src), ffi.sizeof "struct sockaddr_in6"
    if rc < 0
      libc.close fd
      log_warn { action: "refuse_bind_fail", af: "ipv6", err: ffi.errno! }
      return
    dst = ffi.new "struct sockaddr_in6"
    dst.sin6_family = AF_INET6
    dst.sin6_port   = libc.htons dst_port
    ffi.copy dst.sin6_addr, dst_ip_raw, 16
    rc = libc.sendto fd, dns_payload, #dns_payload, 0,
      ffi.cast("struct sockaddr*", dst), ffi.sizeof "struct sockaddr_in6"
    log_warn { action: "sendto_failed", af: "ipv6", err: ffi.errno! } if rc < 0

  libc.close fd

{ :init, :send_refused }
