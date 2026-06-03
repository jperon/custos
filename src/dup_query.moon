-- src/dup_query.moon
-- Duplication d'une question DNS vers un résolveur « validateur » (second avis).
--
-- À partir d'une question UDP autorisée localement, fabrique une copie du paquet
-- où SEULE l'IP destination est réécrite vers le validateur (src client, ports,
-- txid et payload DNS préservés). Les checksums L3/L4 sont recalculés par
-- ipparse.l3.ip lors de la sérialisation. La famille du validateur doit
-- correspondre à celle du paquet client (un paquet IPv4 ne peut aller que vers
-- un validateur IPv4).
--
-- La réinjection sur le pont (AF_PACKET) reste à la charge de l'appelant
-- (worker_questions), via bridge_raw ; ce module ne fait que construire l'octet
-- du paquet IP (sans en-tête Ethernet). TCP non géré (questions UDP seulement).

{ new: new_ip, :s2ip } = require "ipparse.l3.ip"
{ new: new_udp }       = require "ipparse.l4.udp"

PROTO_UDP = 17

--- Choisit dans `resolvers` une IP de la même famille que le paquet client.
-- Détection par présence de ':' (IPv6) dans la chaîne.
-- @tparam table  resolvers Liste d'IP (chaînes), v4 et v6 mélangées.
-- @tparam number version   Version IP du paquet client (4 ou 6).
-- @treturn string|nil Première IP de la bonne famille, ou nil.
pick_resolver = (resolvers, version) ->
  want_v6 = version == 6
  for ip in *(resolvers or {})
    is_v6 = ip\find(":", 1, true) and true or false
    return ip if is_v6 == want_v6
  nil

--- Construit le paquet IP dupliqué (UDP uniquement) vers `validator_ip`.
-- @tparam table   ip       En-tête IP parsé de la question (ipparse l3).
-- @tparam table   l4       En-tête UDP parsé (champ .proto == "udp", .spt, .dpt).
-- @tparam string  dns_raw  Payload DNS brut (question) à transmettre tel quel.
-- @tparam string  validator_ip IP destination du validateur (même famille que ip).
-- @treturn string|nil Octets du paquet IP (sans Ethernet), ou nil si non applicable.
build_udp = (ip, l4, dns_raw, validator_ip) ->
  return nil unless ip and l4 and dns_raw and validator_ip
  return nil unless l4.proto == "udp"
  ok, dst_raw = pcall s2ip, validator_ip
  return nil unless ok and dst_raw
  -- La famille de l'IP validateur doit correspondre à celle du paquet.
  return nil if ip.version == 4 and #dst_raw != 4
  return nil if ip.version == 6 and #dst_raw != 16

  udp = new_udp { spt: l4.spt, dpt: l4.dpt, checksum: 0, data: dns_raw }
  ip_pkt = new_ip {
    version:     ip.version
    v_ihl:       ip.v_ihl
    tos:         ip.tos
    id:          ip.id
    ff:          ip.ff
    ttl:         ip.ttl
    options:     ip.options or ""
    vtf:         ip.vtf
    hop_limit:   ip.hop_limit
    src:         ip.src
    dst:         dst_raw
    protocol:    PROTO_UDP
    next_header: PROTO_UDP
    data:        udp
  }
  "#{ip_pkt}"

{ :pick_resolver, :build_udp }
