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

ffi = require "ffi"
{ new: new_ip, :s2ip } = require "ipparse.l3.ip"
{ new: new_udp }       = require "ipparse.l4.udp"
{ :fix_ip4_cksum, :fix_l4_cksum, :PROTO_UDP } = require "lib.checksums"

-- ── Mémo des IP validateur (octets bruts) ────────────────────────────
-- `s2ip` est un motif + un pack par appel (~0,4 µs IPv4, ~1,6 µs IPv6) : la
-- liste des validateurs est bornée (configuration) et ses IP reviennent à
-- chaque question dupliquée. Cache borné, purge en bloc au débordement.
DST_RAW_MAX = 64
_dst_raw   = {}
_dst_raw_n = 0

--- Octets bruts d'une IP validateur, mémoïsés (nil si texte invalide).
-- @tparam string validator_ip IP textuelle
-- @treturn string|nil 4 ou 16 octets
dst_raw_of = (validator_ip) ->
  return nil unless type(validator_ip) == "string"
  hit = _dst_raw[validator_ip]
  return hit if hit
  ok, raw = pcall s2ip, validator_ip
  return nil unless ok and raw
  if _dst_raw_n >= DST_RAW_MAX
    _dst_raw   = {}
    _dst_raw_n = 0
  _dst_raw[validator_ip] = raw
  _dst_raw_n += 1
  raw

-- Tampon de recopie du chemin rapide (un par processus, alloué au premier
-- appel) : la taille maximale d'un datagramme IP est 65 535 octets.
SCRATCH_SIZE = 65536
_scratch = nil

-- Sélecteurs mémoïsés par liste de résolveurs (identité de table) : le
-- hot-path de duplication appelle get_picker à chaque question, sans allouer.
_pickers = setmetatable {}, __mode: "k"
EMPTY = {}

--- Sépare les IP UDP de `resolvers` par famille (une fois par liste).
-- Les URLs DoH `https://…` ne sont pas des destinations UDP et sont exclues :
-- elles contiennent ':' et seraient sinon prises pour des IPv6.
-- @tparam table resolvers Liste d'IP (chaînes), v4 et v6 mélangées.
-- @treturn table { v4: {...}, v6: {...} }
udp_lists = (resolvers) ->
  lists = { v4: {}, v6: {} }
  for ip in *(resolvers or {})
    continue unless type(ip) == "string"
    continue if ip\find "://", 1, true
    if ip\find ":", 1, true
      lists.v6[#lists.v6 + 1] = ip
    else
      lists.v4[#lists.v4 + 1] = ip
  lists

--- Crée un sélecteur précalculé (listes par famille figées à la construction).
-- `pick(version, dns_id, sport)` renvoie l'IP de la bonne famille d'index
-- `(dns_id + sport) % n + 1` : répartition déterministe par question, sans
-- allocation ni recherche dans la liste à chaque paquet.
-- @tparam table resolvers Liste d'IP (v4/v6 mélangées, URLs DoH ignorées).
-- @treturn function pick(version, dns_id, sport) → string|nil
new_picker = (resolvers) ->
  lists = udp_lists resolvers
  (version, dns_id, sport) ->
    list = if version == 6 then lists.v6 else lists.v4
    n = #list
    return nil if n == 0
    list[((dns_id or 0) + (sport or 0)) % n + 1]

--- Sélecteur mémoïsé pour une liste donnée (cache faible, clé = la table).
-- @tparam table|nil resolvers Liste d'IP (v4/v6 mélangées, URLs DoH ignorées).
-- @treturn function Sélecteur `pick(version, dns_id, sport)`.
get_picker = (resolvers) ->
  resolvers = EMPTY unless resolvers
  p = _pickers[resolvers]
  return p if p
  p = new_picker resolvers
  _pickers[resolvers] = p
  p

--- Choisit la première IP UDP de la même famille que le paquet client.
-- Sert uniquement à vérifier qu'une famille est routable au démarrage ; le
-- choix par paquet (réparti sur toute la famille) passe par `get_picker`.
-- @tparam table  resolvers Liste d'IP (chaînes), v4 et v6 mélangées.
-- @tparam number version   Version IP du paquet client (4 ou 6).
-- @treturn string|nil Première IP UDP de la bonne famille, ou nil.
pick_resolver = (resolvers, version) ->
  pick = get_picker resolvers
  pick version, 0, 0

--- Construit le paquet IP dupliqué (UDP uniquement) vers `validator_ip`.
-- Deux chemins, MÊME sortie (égalité octet à octet vérifiée par
-- tests/unit/dup_query_spec.moon) :
--   * `raw` fourni (production) : recopie du paquet d'origine, réécriture de la
--     seule IP destination, recalcul des checksums IP (v4) et L4 — une copie et
--     deux sommes, au lieu de reconstruire les objets ipparse puis de les
--     sérialiser ;
--   * sans `raw` : reconstruction par ipparse (API historique, tests).
-- @tparam table   ip       En-tête IP parsé de la question (ipparse l3).
-- @tparam table   l4       En-tête UDP parsé (champ .proto == "udp", .spt, .dpt).
-- @tparam string  dns_raw  Payload DNS brut (question) à transmettre tel quel.
-- @tparam string  validator_ip IP destination du validateur (même famille que ip).
-- @tparam[opt] string raw  Paquet IP d'origine (active le chemin par recopie).
-- @treturn string|nil Octets du paquet IP (sans Ethernet), ou nil si non applicable.
build_udp = (ip, l4, dns_raw, validator_ip, raw=nil) ->
  return nil unless ip and l4 and dns_raw and validator_ip
  return nil unless l4.proto == "udp"
  dst_raw = dst_raw_of validator_ip
  return nil unless dst_raw
  -- La famille de l'IP validateur doit correspondre à celle du paquet.
  return nil if ip.version == 4 and #dst_raw != 4
  return nil if ip.version == 6 and #dst_raw != 16

  -- Chemin rapide : la longueur du datagramme vient de l'en-tête UDP (le paquet
  -- d'origine peut porter du bourrage Ethernet au-delà).
  if raw and l4.off and l4.len
    total = l4.off - 1 + l4.len
    if total > 0 and total <= #raw and total <= SCRATCH_SIZE
      _scratch or= ffi.new "uint8_t[?]", SCRATCH_SIZE
      ffi.copy _scratch, raw, total
      -- Offset 0-based de l'IP destination : 16 en IPv4, 24 en IPv6.
      ffi.copy _scratch + (ip.version == 4 and 16 or 24), dst_raw, #dst_raw
      -- IPv6 n'a pas de checksum d'en-tête (RFC 8200 §3).
      if ip.version == 4
        fix_ip4_cksum _scratch, ip.payload_off or 20
      fix_l4_cksum _scratch, total, l4.off - 1, ip.version, PROTO_UDP
      return ffi.string _scratch, total

  udp = new_udp { spt: l4.spt, dpt: l4.dpt, checksum: 0, data: dns_raw }
  ip_pkt = new_ip {
    version:     ip.version
    v_ihl:       ip.v_ihl
    tos:         ip.tos
    id:          ip.id
    ff:          ip.ff
    ttl:         ip.ttl
    options:     ip.options or ""
    traffic_class: ip.traffic_class
    flow_label:  ip.flow_label
    hop_limit:   ip.hop_limit
    src:         ip.src
    dst:         dst_raw
    protocol:    PROTO_UDP
    next_header: PROTO_UDP
    data:        udp
  }
  "#{ip_pkt}"

--- Construit le paquet de RE-REQUÊTE (client → résolveur) à partir des en-têtes
-- de la RÉPONSE captée (src=résolveur, dst=client). Inverse src/dst et ports ;
-- le payload est la requête reconstruite (QR=0). Émis ensuite via raw_send (la
-- réponse du résolveur, adressée au client, repasse par le pont et est
-- recapturée par la NFQUEUE des réponses). UDP uniquement.
-- @tparam table   ip        En-tête IP parsé de la réponse (src=résolveur, dst=client).
-- @tparam table   l4        En-tête UDP parsé de la réponse (.spt=53, .dpt=port client).
-- @tparam string  query_raw Payload DNS de la requête (QR=0).
-- @treturn string|nil Octets du paquet IP (sans Ethernet), ou nil si non applicable.
build_query = (ip, l4, query_raw) ->
  return nil unless ip and l4 and query_raw
  return nil unless l4.proto == "udp"
  udp = new_udp { spt: l4.dpt, dpt: l4.spt, checksum: 0, data: query_raw }
  ip_pkt = new_ip {
    version:     ip.version
    v_ihl:       ip.v_ihl
    tos:         ip.tos
    id:          ip.id
    ff:          ip.ff
    ttl:         64
    options:     ip.options or ""
    traffic_class: ip.traffic_class
    flow_label:  ip.flow_label
    hop_limit:   64
    src:         ip.dst   -- client (spoofé)
    dst:         ip.src   -- résolveur
    protocol:    PROTO_UDP
    next_header: PROTO_UDP
    data:        udp
  }
  "#{ip_pkt}"

{ :pick_resolver, :new_picker, :get_picker, :build_udp, :build_query, :dst_raw_of }
