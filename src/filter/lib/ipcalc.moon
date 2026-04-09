-- src/filter/lib/ipcalc.moon
-- Correspondance CIDR IPv4 et IPv6 via ffi.C.inet_pton.
-- Evite string.pack/unpack (absent en LuaJIT/Lua-5.1).
-- Les adresses IPv4 sont stockées en forme IPv4-mapped (12 octets 0x00/0xFF
-- puis 4 octets d'adresse) pour partager un seul tampon 16 octets.

ffi = require "ffi"

-- inet_pton est déclarée dans ffi_defs via libc ; on l'a aussi dans ffi.C
-- (libc est linkée au processus). On déclare ici uniquement si nécessaire.
pcall ->
  ffi.cdef [[
    int inet_pton(int af, const char *src, void *dst);
  ]]

AF_INET  = 2
AF_INET6 = 10

-- ── Conversion IP → tampon 16 octets ──────────────────────────────
-- Les adresses IPv4 sont stockées aux octets [12..15] avec les 10 premiers
-- à 0x00 et les octets [10..11] à 0xFF (forme IPv4-mapped RFC 4291).
--- Convertit une adresse IP lisible en tampon 16 octets.
-- @tparam string s Adresse IP (IPv4 ou IPv6)
-- @treturn cdata|nil Tampon uint8_t[16] ou nil si l'adresse est invalide
parse_ip = (s) ->
  buf = ffi.new "uint8_t[16]"
  if s\find ":", 1, true
    return buf if ffi.C.inet_pton(AF_INET6, s, buf) == 1
  else
    tmp = ffi.new "uint8_t[4]"
    if ffi.C.inet_pton(AF_INET, s, tmp) == 1
      ffi.fill buf, 10, 0
      buf[10] = 0xFF
      buf[11] = 0xFF
      buf[12] = tmp[0]
      buf[13] = tmp[1]
      buf[14] = tmp[2]
      buf[15] = tmp[3]
      return buf
  nil

-- ── Parsing d'un CIDR ─────────────────────────────────────────────
--- Parse une chaîne CIDR "a.b.c.d/n" ou "::a/n".
-- @tparam string s Chaîne CIDR
-- @treturn table|nil {addr: cdata, mask_bits: number, is_v6: boolean}
parse_net = (s) ->
  addr_s, mask_s = s\match "^([^/]+)/?(%d*)$"
  return nil unless addr_s
  is_v6 = (addr_s\find(":", 1, true) and true) or false
  mask_bits = tonumber(mask_s) or (is_v6 and 128 or 32)
  -- Pour IPv4, le masque porte sur les 32 bits de l'adresse réelle.
  -- Dans notre layout 16 octets, l'adresse IPv4 commence à l'octet 12,
  -- donc on décale le masque de 96 pour travailler uniformément.
  off = is_v6 and 0 or 12
  addr = parse_ip addr_s
  return nil unless addr
  { :addr, :mask_bits, :is_v6, :off }

-- ── Test d'appartenance ────────────────────────────────────────────
bit = require "bit"

--- Vérifie si une adresse IP (tampon 16 octets) appartient au réseau.
-- @tparam cdata  ip_buf Résultat de parse_ip
-- @tparam table  net    Résultat de parse_net
-- @treturn boolean
ip_in_net = (ip_buf, net) ->
  off        = net.off
  mask_bits  = net.mask_bits
  full_bytes = math.floor mask_bits / 8
  rem_bits   = mask_bits % 8

  -- Comparer les octets entiers
  for i = 0, full_bytes - 1
    return false if ip_buf[off + i] ~= net.addr[off + i]

  -- Comparer les bits partiels du dernier octet
  -- ex. rem_bits=3 → mask=0b11100000=0xE0 : ~(0xFF >> 3) & 0xFF
  if rem_bits > 0
    mask = bit.band 0xFF, bit.bnot bit.rshift(0xFF, rem_bits)
    return false if bit.band(ip_buf[off + full_bytes], mask) ~= bit.band(net.addr[off + full_bytes], mask)

  true

-- ── API publique ──────────────────────────────────────────────────
--- Crée un objet réseau avec une méthode contains(ip_string).
-- @tparam string s Chaîne CIDR (ex. "192.168.0.0/16" ou "10.0.0.1")
-- @treturn table|nil Objet {contains: fn} ou nil si invalide
Net = (s) ->
  -- Accepter une IP seule (sans masque) → /32 ou /128
  net = parse_net s
  return nil unless net

  {
    --- Teste si l'adresse IP lisible est dans ce réseau.
    -- @tparam string ip_s Adresse IP lisible
    -- @treturn boolean
    contains: (ip_s) =>
      ip = parse_ip ip_s
      return false unless ip
      ip_in_net ip, net
  }

{ :Net, :parse_ip, :parse_net, :ip_in_net }
