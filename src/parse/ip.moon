-- src/parse/ip.moon
-- Décodage L3 : IPv4 et IPv6.
-- Travaille directement sur la string Lua du payload brut (pas de copie).
-- Toutes les fonctions retournent nil en cas de paquet trop court ou invalide.

{ :ffi, :libc } = require "ffi_defs"
{ :PROTO_UDP, :AF_INET, :AF_INET6 } = require "config"

bit = require "bit"

-- ── Helpers ──────────────────────────────────────────────────────

-- Lecture big-endian depuis une string Lua (offset 1-based)
read_u8  = (s, i)    -> s\byte i
read_u16 = (s, i)    -> bit.bor bit.lshift(s\byte(i), 8), s\byte(i+1)
-- bit.lshift travaille sur des int32 signés : un octet haut >= 0x80 déborde.
-- On force l'arithmétique non signée via ffi uint32_t avant tonumber().
read_u32 = (s, i)    ->
  tonumber ffi.new "uint32_t",
    bit.bor(
      bit.lshift(s\byte(i),   24),
      bit.lshift(s\byte(i+1), 16),
      bit.lshift(s\byte(i+2),  8),
      s\byte(i+3)
    )

-- Formate 4 octets (offset 1-based dans la string) en "a.b.c.d"
format_ipv4 = (s, i) ->
  "#{s\byte i}.#{s\byte i+1}.#{s\byte i+2}.#{s\byte i+3}"

-- Formate 16 octets (offset 1-based) en notation IPv6 compressée simple
-- (pas de compression ::, suffisant pour les logs)
format_ipv6 = (s, i) ->
  groups = for g = 0, 7
    string.format "%x", read_u16 s, i + g*2
  table.concat groups, ":"

-- ── IPv4 ─────────────────────────────────────────────────────────

-- Parse le header IPv4. Retourne nil si le paquet est trop court ou non-UDP.
-- Résultat : { src_ip, dst_ip, src_ip_raw (4 bytes string), protocol,
--              ihl (bytes), total_len, version=4 }
parse_ipv4 = (raw) ->
  return nil if #raw < 20

  version = bit.rshift bit.band(read_u8(raw, 1), 0xF0), 4
  return nil if version != 4

  ihl      = bit.band(read_u8(raw, 1), 0x0F) * 4   -- longueur header en octets
  total_len = read_u16 raw, 3
  protocol  = read_u8 raw, 10

  return nil if #raw < ihl

  src_ip     = format_ipv4 raw, 13
  dst_ip     = format_ipv4 raw, 17
  src_ip_raw = raw\sub 13, 16   -- 4 octets bruts pour l'IPC
  dst_ip_raw = raw\sub 17, 20

  {
    version: 4
    :ihl, :total_len, :protocol
    :src_ip, :dst_ip
    :src_ip_raw, :dst_ip_raw
    af: AF_INET
  }

-- Recalcul du checksum IP (en-tête seulement).
-- Utilisé après modification du payload pour patcher le champ checksum.
-- raw_header : string Lua des IHL premiers octets (avec checksum à 0)
checksum_ip = (raw_header) ->
  sum = 0
  i   = 1
  while i < #raw_header
    sum += read_u16 raw_header, i
    i   += 2
  -- fold carries
  while sum > 0xFFFF
    sum = bit.band(sum, 0xFFFF) + bit.rshift(sum, 16)
  bit.band bit.bnot(sum), 0xFFFF

-- ── IPv6 ─────────────────────────────────────────────────────────

-- Parse le header IPv6 fixe (40 octets).
-- Retourne nil si non-UDP ou paquet trop court.
parse_ipv6 = (raw) ->
  return nil if #raw < 40

  version = bit.rshift bit.band(read_u8(raw, 1), 0xF0), 4
  return nil if version != 6

  -- next_header est à l'octet 7 (offset 6, 0-based)
  next_header = read_u8 raw, 7
  -- On ne gère pas les extension headers dans ce POC
  return nil if next_header != PROTO_UDP

  src_ip     = format_ipv6 raw, 9
  dst_ip     = format_ipv6 raw, 25
  src_ip_raw = raw\sub 9, 24    -- 16 octets bruts
  dst_ip_raw = raw\sub 25, 40

  {
    version: 6
    ihl: 40
    protocol: next_header
    :src_ip, :dst_ip
    :src_ip_raw, :dst_ip_raw
    af: AF_INET6
  }

-- Détecte la version IP et dispatche sur parse_ipv4 / parse_ipv6
parse_ip = (raw) ->
  return nil if #raw < 1
  version = bit.rshift bit.band(read_u8(raw, 1), 0xF0), 4
  switch version
    when 4 then parse_ipv4 raw
    when 6 then parse_ipv6 raw
    else nil

{ :parse_ip, :parse_ipv4, :parse_ipv6
  :checksum_ip, :format_ipv4, :format_ipv6
  :read_u8, :read_u16, :read_u32 }
