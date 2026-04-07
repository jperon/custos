-- src/parse/ip.moon
-- Décodage L3 : IPv4 et IPv6.
-- Travaille directement sur la string Lua du payload brut (pas de copie).
-- Toutes les fonctions retournent nil en cas de paquet trop court ou invalide.

{ :ffi, :libc } = require "ffi_defs"
{ :PROTO_UDP, :AF_INET, :AF_INET6 } = require "config"

bit = require "bit"

-- ── Helpers ──────────────────────────────────────────────────────

--- Lit un octet à l'offset i (1-based) d'une string.
-- @tparam string s  Chaîne source
-- @tparam number i  Offset 1-based
-- @treturn number valeur de l'octet (0–255)
read_u8  = (s, i)    -> s\byte i

--- Lit un mot de 16 bits big-endian à l'offset i (1-based).
-- @tparam string s  Chaîne source
-- @tparam number i  Offset 1-based
-- @treturn number valeur uint16
read_u16 = (s, i)    -> bit.bor bit.lshift(s\byte(i), 8), s\byte(i+1)
-- bit.lshift travaille sur des int32 signés : un octet haut >= 0x80 déborde.
-- On force l'arithmétique non signée via ffi uint32_t avant tonumber().

--- Lit un mot de 32 bits big-endian à l'offset i (1-based).
-- @tparam string s  Chaîne source
-- @tparam number i  Offset 1-based
-- @treturn number valeur uint32
read_u32 = (s, i)    ->
  tonumber ffi.new "uint32_t",
    bit.bor(
      bit.lshift(s\byte(i),   24),
      bit.lshift(s\byte(i+1), 16),
      bit.lshift(s\byte(i+2),  8),
      s\byte(i+3)
    )

--- Formate 4 octets à l'offset i en chaîne "a.b.c.d".
-- @tparam string s  Chaîne source
-- @tparam number i  Offset 1-based du premier octet
-- @treturn string adresse IPv4 texte
format_ipv4 = (s, i) ->
  "#{s\byte i}.#{s\byte i+1}.#{s\byte i+2}.#{s\byte i+3}"

--- Formate 16 octets à l'offset i en notation IPv6 (groupes séparés par ':').
-- Note : pas de compression ::.
-- @tparam string s  Chaîne source
-- @tparam number i  Offset 1-based du premier octet
-- @treturn string adresse IPv6 texte
format_ipv6 = (s, i) ->
  groups = for g = 0, 7
    string.format "%x", read_u16 s, i + g*2
  table.concat groups, ":"

-- ── IPv4 ─────────────────────────────────────────────────────────

--- Parse le header IPv4 d'un paquet brut.
-- @tparam  string     raw Paquet IP brut (début du header IP)
-- @treturn table|nil  {version, ihl, total_len, protocol, src_ip, dst_ip,
--                      src_ip_raw, dst_ip_raw, af} ou nil si invalide
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

--- Recalcule le checksum du header IPv4 (RFC 791).
-- Le champ checksum du header doit être mis à zéro avant l'appel.
-- @tparam  string raw_header Les IHL premiers octets du paquet (checksum=0)
-- @treturn number Checksum uint16
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

-- Extension header types skippable in the legacy (string-based) parser.
-- true  = standard formula: (Hdr Ext Len + 1) × 8 bytes
-- false = AH (RFC 4302):    (Payload Len  + 2) × 4 bytes
-- ESP (50) is absent: encrypted payload, L4 unreachable.
IPV6_EXT_HDRS_LEGACY = {
  [0]:   true   -- Hop-by-Hop Options
  [43]:  true   -- Routing
  [44]:  true   -- Fragment
  [51]:  false  -- Authentication Header
  [60]:  true   -- Destination Options
  [135]: true   -- Mobility
  [139]: true   -- HIP
  [140]: true   -- Shim6
}

--- Parse le header IPv6 fixe (40 octets) d'un paquet brut en sautant
-- les extension headers éventuels (RFC 2460, RFC 4302).
-- @tparam  string    raw Paquet IP brut (début du header IPv6)
-- @treturn table|nil {version=6, ihl=l4_off, protocol, src_ip, dst_ip,
--                     src_ip_raw, dst_ip_raw, af} ou nil si invalide/non-UDP
parse_ipv6 = (raw) ->
  return nil if #raw < 40

  version = bit.rshift bit.band(read_u8(raw, 1), 0xF0), 4
  return nil if version != 6

  -- Parcours des extension headers.
  -- Les indices sont 1-based (chaînes Lua) ; l'en-tête fixe fait 40 octets.
  nh  = read_u8 raw, 7   -- Next Header dans l'en-tête fixe (octet 7)
  off = 41               -- offset 1-based du premier octet après l'en-tête fixe

  while IPV6_EXT_HDRS_LEGACY[nh] != nil
    return nil if off + 1 > #raw    -- besoin d'au moins 2 octets (NH + Len)
    next_nh  = read_u8 raw, off
    ext_size = if nh == 51
      (read_u8(raw, off + 1) + 2) * 4    -- AH
    else
      (read_u8(raw, off + 1) + 1) * 8    -- formule standard
    return nil if ext_size < 8 or off - 1 + ext_size > #raw
    off += ext_size
    nh   = next_nh

  return nil if nh != PROTO_UDP

  l4_off     = off - 1   -- offset 0-based du header L4
  src_ip     = format_ipv6 raw, 9
  dst_ip     = format_ipv6 raw, 25
  src_ip_raw = raw\sub 9, 24    -- 16 octets bruts
  dst_ip_raw = raw\sub 25, 40

  {
    version: 6
    ihl: l4_off
    protocol: nh
    :src_ip, :dst_ip
    :src_ip_raw, :dst_ip_raw
    af: AF_INET6
  }

--- Détecte la version IP (4 ou 6) et dispatche sur parse_ipv4 / parse_ipv6.
-- @tparam  string     raw Paquet IP brut
-- @treturn table|nil  Résultat du parser correspondant ou nil si inconnu
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
