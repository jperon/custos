-- src/raw_send.moon
-- Émission d'un paquet IP « routé » par le noyau, pour la duplication de
-- question du second avis. Contrairement à AF_PACKET (L2, qui exige de connaître
-- la MAC du next-hop), on utilise un socket RAW avec en-tête fourni :
--   • IPv4 : socket(AF_INET, SOCK_RAW, IPPROTO_RAW) → IP_HDRINCL implicite ;
--   • IPv6 : socket(AF_INET6, SOCK_RAW, IPPROTO_UDP) + IPV6_HDRINCL.
-- On fournit l'en-tête IP complet (src = IP client spoofée, dst = validateur) et
-- le NOYAU décide du routage (next-hop, interface de sortie). Cela gère
-- nativement un IPv6 routé par un tunnel (WireGuard) distinct de la route IPv4.
--
-- La réponse du validateur, adressée à l'IP client, revient par le chemin normal
-- et traverse le pont → captée par la file NFQUEUE des réponses.

{ :ffi } = require "ffi_defs"
{ :C, :AF_INET, :AF_INET6, :SOCK_RAW, :SOCK_DGRAM } = require "lib.socket"
{ :s2ip } = require "ipparse.l3.ip"

IPPROTO_UDP  = 17
IPPROTO_RAW  = 255
IPPROTO_IPV6 = 41
IPV6_HDRINCL = 36

--- Ouvre le socket RAW pour une famille (4 ou 6). HDRINCL activé.
-- @tparam number version 4 ou 6
-- @treturn number|nil fd, ou nil + errno
open = (version) ->
  if version == 6
    fd = C.socket AF_INET6, SOCK_RAW, IPPROTO_UDP
    return nil, ffi.errno! if fd < 0
    one = ffi.new "int[1]", 1
    C.setsockopt fd, IPPROTO_IPV6, IPV6_HDRINCL, one, ffi.sizeof("int")
    fd
  else
    fd = C.socket AF_INET, SOCK_RAW, IPPROTO_RAW
    return nil, ffi.errno! if fd < 0
    fd

-- Construit le sockaddr destination (port indifférent pour un socket RAW).
_dest_addr = (version, dst_raw) ->
  if version == 6
    sa = ffi.new "struct sockaddr_in6"
    sa.sin6_family = AF_INET6
    ffi.copy sa.sin6_addr, dst_raw, 16
    sa, ffi.sizeof("struct sockaddr_in6")
  else
    sa = ffi.new "struct sockaddr_in"
    sa.sin_family = AF_INET
    ffi.copy sa.sin_addr, dst_raw, 4
    sa, ffi.sizeof("struct sockaddr_in")

--- Envoie un paquet IP brut vers `dst_ip` (laisse le noyau router).
-- @tparam number fd      Socket ouvert par open(version).
-- @tparam number version 4 ou 6
-- @tparam string pkt     Octets du paquet IP (en-tête inclus, cf. dup_query).
-- @tparam string dst_ip  IP destination (validateur), même famille que version.
-- @treturn boolean true si tous les octets ont été émis.
send = (fd, version, pkt, dst_ip) ->
  return false unless fd and pkt and dst_ip
  ok, dst_raw = pcall s2ip, dst_ip
  return false unless ok and dst_raw
  sa, salen = _dest_addr version, dst_raw
  n = C.sendto fd, pkt, #pkt, 0, ffi.cast("const struct sockaddr*", sa), salen
  n == #pkt

--- Teste s'il existe une route vers `dst_ip` (connect UDP, aucun paquet émis).
-- Sert à n'activer une famille que si elle est routable (ex. pas d'IPv6 → on
-- évite de parquer/dupliquer pour rien).
-- @tparam number version 4 ou 6
-- @tparam string dst_ip  IP du validateur
-- @treturn boolean true si routable.
routable = (version, dst_ip) ->
  return false unless dst_ip
  ok, dst_raw = pcall s2ip, dst_ip
  return false unless ok and dst_raw
  af = version == 6 and AF_INET6 or AF_INET
  fd = C.socket af, SOCK_DGRAM, IPPROTO_UDP
  return false if fd < 0
  sa, salen = _dest_addr version, dst_raw
  rc = C.connect fd, ffi.cast("const struct sockaddr*", sa), salen
  C.close fd
  rc == 0

{ :open, :send, :routable, :IPPROTO_RAW, :IPPROTO_UDP }
