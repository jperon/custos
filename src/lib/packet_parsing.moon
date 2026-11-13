-- src/lib/packet_parsing.moon
-- Agrégateur des primitives de parsing L3/L4/L7 issues d'ipparse, partagées par
-- les workers NFQUEUE qui décodent un paquet (worker_questions, worker_responses).
-- Évite de répéter le même bloc de `require` (un par module ipparse) dans chaque
-- worker. Ré-exporte ipparse à l'identique, sauf `ip2s` (mémoïsé, cf. plus bas).

{ parse: parse_ip4 }            = require "ipparse.l3.ip4"
{ parse: parse_ip6 }            = require "ipparse.l3.ip6"
{ parse: parse_udp }            = require "ipparse.l4.udp"
{ parse: parse_tcp }            = require "ipparse.l4.tcp"
{ parse: parse_dns, :types }    = require "ipparse.l7.dns"
{ ip2s: ipparse_ip2s }          = require "ipparse.l3.ip"

-- ── Conversion IPv4 → texte mémoïsée ─────────────────────────────────
-- `ip2s` d'ipparse fait `string.format "%d.%d.%d.%d"` sur un dépaquetage :
-- mesuré 0,3 µs par appel (make bench-hotpath --micro). Un worker convertit les
-- MÊMES adresses à chaque paquet — le client et le résolveur sur chaque paquet,
-- les 8 adresses d'une réponse dans `parse_answers` — et les adresses d'un
-- profil réel se répètent (cache DNS en amont, CDN). Cache borné, purge en
-- bloc, conversion pure : la valeur rendue est identique.
-- Les IPv6 (16 octets) ne sont pas mémoïsées (formes plus variées, clé plus
-- longue).
IP2S_CACHE_MAX = 512
_ip4s_cache = {}
_ip4s_n     = 0

--- Convertit une adresse IP brute (4 ou 16 octets) en texte.
-- @tparam string|nil raw Adresse brute
-- @treturn string|nil Adresse textuelle, ou nil si la longueur est invalide
ip2s = (raw) ->
  return nil unless raw
  return ipparse_ip2s raw unless #raw == 4
  hit = _ip4s_cache[raw]
  return hit if hit
  s = ipparse_ip2s raw
  if _ip4s_n >= IP2S_CACHE_MAX
    _ip4s_cache = {}
    _ip4s_n     = 0
  _ip4s_cache[raw] = s
  _ip4s_n += 1
  s

{ :parse_ip4, :parse_ip6, :parse_udp, :parse_tcp, :parse_dns, :ip2s, dns_types: types }
