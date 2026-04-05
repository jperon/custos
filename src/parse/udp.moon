-- src/parse/udp.moon
-- Décodage L4 : UDP.
-- Fournit aussi le recalcul du checksum UDP (nécessaire après patch TTL DNS).

{ :read_u16 } = require "parse/ip"
{ :DNS_PORT } = require "config"

-- Header UDP : 8 octets
--   0-1 : src_port
--   2-3 : dst_port
--   4-5 : length (header + data)
--   6-7 : checksum

UDP_HEADER_LEN = 8

-- Parse le header UDP à partir de l'offset ihl dans le payload brut.
-- Retourne nil si le paquet est trop court ou si ce n'est pas du DNS (port 53).
-- ip_hdr : résultat de parse_ip (pour ihl et version)
parse_udp = (raw, ip_hdr) ->
  udp_off = ip_hdr.ihl + 1   -- offset 1-based dans raw

  return nil if #raw < udp_off + UDP_HEADER_LEN - 1

  src_port  = read_u16 raw, udp_off
  dst_port  = read_u16 raw, udp_off + 2
  udp_len   = read_u16 raw, udp_off + 4

  -- On ne filtre pas ici sur le port : le worker reçoit uniquement UDP/53
  -- via les règles nft, mais on vérifie quand même par sécurité.
  return nil if src_port != DNS_PORT and dst_port != DNS_PORT

  payload_off = udp_off + UDP_HEADER_LEN   -- offset 1-based du payload DNS

  {
    :src_port, :dst_port, :udp_len
    payload_off: payload_off
    -- Sous-string du payload DNS (sans copie en Lua 5.1 si <= 40 octets,
    -- string.sub copie sinon — acceptable pour notre usage)
    dns_payload: raw\sub payload_off
    udp_off: udp_off
  }

-- Calcul du pseudo-header UDP IPv4 pour le checksum.
-- Nécessaire car le checksum UDP couvre src_ip + dst_ip + proto + udp_len.
-- Retourne la somme partielle (uint32) à intégrer dans checksum_udp.
pseudo_header_sum_v4 = (src_ip_raw, dst_ip_raw, udp_len) ->
  sum = 0
  -- src_ip : 4 octets → 2 mots de 16 bits
  sum += read_u16 src_ip_raw, 1
  sum += read_u16 src_ip_raw, 3
  -- dst_ip : idem
  sum += read_u16 dst_ip_raw, 1
  sum += read_u16 dst_ip_raw, 3
  -- protocol UDP = 17, zero byte
  sum += 17
  -- UDP length
  sum += udp_len
  sum

--- Calcul du pseudo-header UDP IPv6 pour le checksum (RFC 2460 §8.1).
-- Le pseudo-header IPv6 contient :
--   src_addr (16 octets) + dst_addr (16 octets)
--   + upper-layer length (32 bits) + zero (24 bits) + next_header (8 bits)
-- @tparam string src_ip_raw 16 octets bruts de l'adresse source
-- @tparam string dst_ip_raw 16 octets bruts de l'adresse destination
-- @tparam number udp_len    longueur du segment UDP (header + data)
-- @treturn number somme partielle (accumulation uint32) du pseudo-header
pseudo_header_sum_v6 = (src_ip_raw, dst_ip_raw, udp_len) ->
  sum = 0
  -- src_ip : 16 octets → 8 mots de 16 bits
  for i = 1, 15, 2
    sum += read_u16 src_ip_raw, i
  -- dst_ip : idem
  for i = 1, 15, 2
    sum += read_u16 dst_ip_raw, i
  -- upper-layer packet length (32 bits big-endian)
  -- Pour udp_len < 65536 : high word = 0, low word = udp_len
  sum += udp_len
  -- zero (24 bits) + next header (8 bits) = 0x0000 et 0x0011 (UDP = 17)
  sum += 17
  sum

--- Recalcul complet du checksum UDP sur le payload brut modifié.
-- Dispatche sur IPv4 ou IPv6 selon ip_hdr.version.
-- @tparam string raw     paquet IP complet (modifié)
-- @tparam table  ip_hdr  résultat de parse_ip
-- @tparam table  udp_hdr résultat de parse_udp
-- @treturn number checksum (uint16) à écrire aux octets udp_off+6 / udp_off+7
checksum_udp = (raw, ip_hdr, udp_hdr) ->
  { :read_u16 } = require "parse/ip"
  bit = require "bit"

  sum = if ip_hdr.version == 6
    pseudo_header_sum_v6(
      ip_hdr.src_ip_raw, ip_hdr.dst_ip_raw, udp_hdr.udp_len
    )
  else
    pseudo_header_sum_v4(
      ip_hdr.src_ip_raw, ip_hdr.dst_ip_raw, udp_hdr.udp_len
    )

  -- Somme de tous les mots 16 bits du segment UDP (header + data),
  -- en mettant le champ checksum à zéro
  udp_start = udp_hdr.udp_off   -- 1-based
  udp_end   = udp_start + udp_hdr.udp_len - 1
  i         = udp_start
  cksum_off = udp_start + 6    -- offset du champ checksum dans raw

  while i <= udp_end
    -- Le checksum doit être traité comme zéro
    word = if i == cksum_off
      0
    elseif i + 1 <= udp_end
      read_u16 raw, i
    else
      -- Dernier octet impair : padder avec zéro
      bit.lshift raw\byte(i), 8
    sum += word
    i   += 2

  -- Fold carries
  while sum > 0xFFFF
    sum = bit.band(sum, 0xFFFF) + bit.rshift(sum, 16)

  bit.band bit.bnot(sum), 0xFFFF

{ :parse_udp, :checksum_udp, :pseudo_header_sum_v4, :pseudo_header_sum_v6, :UDP_HEADER_LEN }
