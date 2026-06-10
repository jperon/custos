-- src/lib/checksums.moon
-- Helpers byte-level (big-endian) et recalcul de checksums IPv4/UDP/TCP sur des
-- buffers FFI uint8_t*, partagés par les workers qui patchent un paquet en place
-- (worker_responses, et tout futur worker réécrivant un payload L4).
--
-- Distinct de `ipparse.l3.lib` (checksum) qui opère sur des chaînes Lua : ici on
-- mute directement le buffer FFI, sans allocation.

bit = require "bit"

PROTO_UDP = 17
PROTO_TCP = 6

--- Lit un entier 16 bits big-endian à l'offset 0-based o.
r16 = (p, o) ->
  bit.bor bit.lshift(p[o], 8), p[o + 1]

--- Écrit un entier 32 bits big-endian à l'offset 0-based o.
w32 = (p, o, v) ->
  p[o]   = bit.band bit.rshift(v, 24), 0xFF
  p[o+1] = bit.band bit.rshift(v, 16), 0xFF
  p[o+2] = bit.band bit.rshift(v,  8), 0xFF
  p[o+3] = bit.band v, 0xFF

--- Écrit un entier 16 bits big-endian à l'offset 0-based o.
w16 = (p, o, v) ->
  p[o]   = bit.band bit.rshift(v, 8), 0xFF
  p[o+1] = bit.band v, 0xFF

--- Replie une somme 32 bits en complément à un sur 16 bits.
fold16 = (sum) ->
  while bit.rshift(sum, 16) != 0
    sum = bit.band(sum, 0xFFFF) + bit.rshift(sum, 16)
  sum

--- Recalcule en place le checksum d'en-tête IPv4.
-- @tparam cdata  buf Paquet IP (uint8_t*)
-- @tparam number ihl Longueur de l'en-tête IPv4 en octets
fix_ip4_cksum = (buf, ihl) ->
  buf[10] = 0
  buf[11] = 0
  sum = 0
  for i = 0, ihl - 1, 2
    sum += bit.bor bit.lshift(buf[i], 8), buf[i + 1]
  w16 buf, 10, bit.band(bit.bnot(fold16 sum), 0xFFFF)

-- Plage [first, last] (octets, pas de 2) du pseudo-header d'adresses sommé
-- pour le checksum L4 : src+dst IPv4 (12-18) ou IPv6 (8-38).
PH_FIRST = { [4]: 12, [6]: 8 }
PH_LAST  = { [4]: 18, [6]: 38 }

--- Recalcule en place le checksum L4 (UDP ou TCP, IPv4 ou IPv6).
-- Longueur L4 : champ length UDP, ou pkt_len - l4_off en TCP.
-- @tparam cdata  buf     Paquet IP (uint8_t*)
-- @tparam number pkt_len Longueur totale du paquet
-- @tparam number l4_off  Offset 0-based de l'en-tête L4
-- @tparam number version 4 ou 6
-- @tparam number proto   PROTO_UDP ou PROTO_TCP
fix_l4_cksum = (buf, pkt_len, l4_off, version, proto) ->
  is_udp = proto == PROTO_UDP
  return if pkt_len < l4_off + (is_udp and 8 or 20)
  l4_len = is_udp and r16(buf, l4_off + 4) or pkt_len - l4_off
  cksum_off = l4_off + (is_udp and 6 or 16)
  buf[cksum_off] = 0
  buf[cksum_off + 1] = 0
  sum = 0
  for i = PH_FIRST[version], PH_LAST[version], 2
    sum += r16 buf, i
  sum += proto
  sum += l4_len
  l4_end = l4_off + l4_len
  l4_end = pkt_len if l4_end > pkt_len
  i = l4_off
  while i < l4_end
    word = if i == cksum_off then 0
    elseif i + 1 < l4_end then r16 buf, i
    else bit.lshift buf[i], 8
    sum += word
    i += 2
  cksum = bit.band bit.bnot(fold16 sum), 0xFFFF
  cksum = 0xFFFF if cksum == 0
  w16 buf, cksum_off, cksum

{ :r16, :w16, :w32, :fold16, :fix_ip4_cksum, :fix_l4_cksum, :PROTO_UDP, :PROTO_TCP }
