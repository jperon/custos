-- src/refuse.moon
-- Envoi de réponses DNS REFUSED (RCODE 5 + EDE Filtered) aux clients bloqués.
--
-- Ouvre deux sockets UDP liés au port 53 (SO_REUSEPORT) :
--   • AF_INET  pour les clients IPv4
--   • AF_INET6 pour les clients IPv6
-- Le noyau remplit les headers IP et UDP ; la source port = 53 permet
-- au client de reconnaître la réponse comme provenant du résolveur.

{ :ffi, :libc } = require "ffi_defs"
{ :AF_INET, :AF_INET6 } = require "config"
{ :log_warn, :log_info } = require "log"

-- ── Constantes POSIX ─────────────────────────────────────────────
SOCK_DGRAM   = 2
SOL_SOCKET   = 1
SO_REUSEADDR = 2
SO_REUSEPORT = 15   -- Linux (x86/arm64/riscv)

-- ── État du module (fds ouverts une seule fois au démarrage) ─────
sock4 = -1   -- fd IPv4, −1 = non disponible
sock6 = -1   -- fd IPv6, −1 = non disponible

-- ── Ouverture interne ────────────────────────────────────────────

--- Ouvre un socket SOCK_DGRAM lié à *:53 pour la famille d'adresses af.
-- @tparam  number  af  AF_INET (2) ou AF_INET6 (10)
-- @treturn number  fd ≥ 0 en cas de succès
-- @treturn string  message d'erreur si fd < 0
open_udp53 = (af) ->
  fd = libc.socket af, SOCK_DGRAM, 0
  return -1, "socket() echec" if fd < 0

  -- Autorise plusieurs bind() sur le même port (cohabitation avec dnsmasq, etc.)
  one = ffi.new "int[1]", 1
  libc.setsockopt fd, SOL_SOCKET, SO_REUSEADDR, one, ffi.sizeof "int"
  libc.setsockopt fd, SOL_SOCKET, SO_REUSEPORT, one, ffi.sizeof "int"

  rc = if af == AF_INET
    addr = ffi.new "struct sockaddr_in"
    addr.sin_family = AF_INET
    addr.sin_port   = libc.htons 53
    -- sin_addr = INADDR_ANY (déjà à zéro)
    libc.bind fd, ffi.cast("struct sockaddr*", addr), ffi.sizeof "struct sockaddr_in"
  else
    addr = ffi.new "struct sockaddr_in6"
    addr.sin6_family = AF_INET6
    addr.sin6_port   = libc.htons 53
    -- sin6_addr = in6addr_any (déjà à zéro)
    libc.bind fd, ffi.cast("struct sockaddr*", addr), ffi.sizeof "struct sockaddr_in6"

  if rc < 0
    libc.close fd
    return -1, "bind() echec (af=#{af})"

  fd, nil

-- ── API publique ─────────────────────────────────────────────────

--- Initialise le module : ouvre les sockets IPv4 et IPv6.
-- À appeler une seule fois après fork(), avant le traitement des paquets.
-- @treturn nil
init = ->
  fd4, err4 = open_udp53 AF_INET
  if fd4 < 0
    log_warn { action: "refuse_init_fail", af: "ipv4", err: tostring err4 }
  else
    sock4 = fd4
    log_info { action: "refuse_ready", af: "ipv4" }

  fd6, err6 = open_udp53 AF_INET6
  if fd6 < 0
    log_warn { action: "refuse_init_fail", af: "ipv6", err: tostring err6 }
  else
    sock6 = fd6
    log_info { action: "refuse_ready", af: "ipv6" }

--- Envoie un payload DNS en UDP vers l'adresse et le port indiqués.
-- Le paquet sortant a pour source port 53 (bind au démarrage).
-- @tparam string dst_ip_raw  4 octets (IPv4) ou 16 octets (IPv6) bruts
-- @tparam number dst_port    Port destination (src_port de la question d'origine)
-- @tparam string dns_payload Payload DNS de la réponse (chaîne binaire)
-- @tparam number af          AF_INET ou AF_INET6
-- @treturn nil
send_refused = (dst_ip_raw, dst_port, dns_payload, af) ->
  if af == AF_INET
    return if sock4 < 0
    addr = ffi.new "struct sockaddr_in"
    addr.sin_family = AF_INET
    addr.sin_port   = libc.htons dst_port
    ffi.copy addr.sin_addr, dst_ip_raw, 4
    rc = libc.sendto sock4, dns_payload, #dns_payload, 0,
      ffi.cast("struct sockaddr*", addr), ffi.sizeof "struct sockaddr_in"
    log_warn { action: "sendto_failed", af: "ipv4" } if rc < 0
  else
    return if sock6 < 0
    addr = ffi.new "struct sockaddr_in6"
    addr.sin6_family = AF_INET6
    addr.sin6_port   = libc.htons dst_port
    ffi.copy addr.sin6_addr, dst_ip_raw, 16
    rc = libc.sendto sock6, dns_payload, #dns_payload, 0,
      ffi.cast("struct sockaddr*", addr), ffi.sizeof "struct sockaddr_in6"
    log_warn { action: "sendto_failed", af: "ipv6" } if rc < 0

{ :init, :send_refused }
