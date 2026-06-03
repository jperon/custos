-- src/dns_classify.moon
-- Classification d'une réponse DNS « second avis » (résolveur validateur).
--
-- À partir de la réponse du validateur (B), décide :
--   * block    : rcode NXDOMAIN          → blocage par NXDOMAIN synthétique.
--   * sinkhole : réponse NOERROR dont toutes les adresses sont nulles
--                (0.0.0.0 / ::) → blocage en REPRODUISANT le sinkhole + EDE.
--                DNSforFamily bloque ainsi (pas par NXDOMAIN) ; on renvoie au
--                client la même sémantique (adresses nulles) plutôt qu'un
--                NXDOMAIN. Porte les A/AAAA nulles + le ttl du validateur.
--   * redirect : présence d'un CNAME     → réorientation (ex. SafeSearch) ;
--                porte la cible CNAME + les A/AAAA fournis par le validateur.
--   * pass     : réponse normale         → laisser passer la réponse d'origine.
--
-- Un CNAME n'est PAS un blocage : les CDN répondent massivement en CNAME. Il
-- s'agit d'une réorientation, qu'on n'applique que si la réponse d'origine (A)
-- ne porte pas déjà la même cible CNAME (cf. `has_cname_target`).
--
-- Module pur : opère sur un message DNS déjà parsé (`ipparse.l7.dns`) plus le
-- payload brut et l'offset L7 (nécessaires pour décompresser les noms CNAME).

dns_mod = require "ipparse.l7.dns"
{ :labels, :types } = dns_mod
{ :concat } = table
bit = require "bit"

CNAME    = types.CNAME
A        = types.A
AAAA     = types.AAAA
NXDOMAIN = dns_mod.rcodes.NXDOMAIN

--- Valeur numérique du rcode (l'accesseur `header.rcode` renvoie un booléen).
-- @tparam table header En-tête DNS parsé.
-- @treturn number rcode (0-15)
numeric_rcode = (header) ->
  bit.band (header and header.ra_z_rcode or 0), 0x0f

--- Décode le nom cible d'un RR CNAME (rdata = nom potentiellement compressé).
-- @tparam table   rr      RR parsé (rtype CNAME), avec `.rdata` et `.end_off`.
-- @tparam string  raw     Payload DNS brut complet.
-- @tparam[opt=1]  number l7_off Offset L7 (base des pointeurs de compression).
-- @treturn string|nil Nom cible en minuscules, ou nil si indécodable.
decode_cname_target = (rr, raw, l7_off=1) ->
  return nil unless rr and rr.rdata and rr.end_off and raw
  rdata_start = rr.end_off - #rr.rdata + 1
  return nil if rdata_start < 1
  lbls = labels raw, rdata_start, l7_off
  return nil unless lbls and #lbls > 0
  concat(lbls, ".")\lower!

--- Liste des cibles CNAME présentes dans la section answer d'un message.
-- @tparam table  dns    Message DNS parsé.
-- @tparam string raw    Payload DNS brut complet.
-- @tparam[opt=1] number l7_off Offset L7.
-- @treturn table Liste (éventuellement vide) de noms cibles en minuscules.
cname_targets = (dns, raw, l7_off=1) ->
  out = {}
  for rr in *(dns and dns.answers or {})
    if rr.rtype == CNAME
      if target = decode_cname_target rr, raw, l7_off
        out[#out + 1] = target
  out

--- Vrai si le message porte un CNAME vers `target` (comparaison insensible à la casse).
-- @tparam table  dns    Message DNS parsé (ex. réponse d'origine A).
-- @tparam string raw    Payload brut correspondant.
-- @tparam string target Nom cible recherché.
-- @tparam[opt=1] number l7_off Offset L7.
-- @treturn boolean
has_cname_target = (dns, raw, target, l7_off=1) ->
  return false unless target and target != ""
  want = target\lower!
  for t in *cname_targets dns, raw, l7_off
    return true if t == want
  false

--- Vrai si rdata est une adresse « nulle » (sinkhole) : 0.0.0.0 ou ::.
-- @tparam string rdata Données brutes d'un RR A (4 octets) ou AAAA (16 octets).
-- @treturn boolean
is_sinkhole_addr = (rdata) ->
  return false unless rdata and (#rdata == 4 or #rdata == 16)
  for i = 1, #rdata
    return false if rdata\byte(i) != 0
  true

--- Vrai si la réponse est un sinkhole : elle porte au moins une adresse et
-- toutes ses adresses (A/AAAA) sont nulles (0.0.0.0 / ::).
-- @tparam table dns Message DNS parsé.
-- @treturn boolean
is_sinkhole = (dns) ->
  seen = false
  for rr in *(dns and dns.answers or {})
    if rr.rtype == A or rr.rtype == AAAA
      return false unless is_sinkhole_addr rr.rdata
      seen = true
  seen

--- Classe la réponse du validateur.
-- @tparam table  dns    Message DNS parsé (réponse validateur B).
-- @tparam string raw    Payload DNS brut de B.
-- @tparam[opt=1] number l7_off Offset L7.
-- @treturn table { verdict = "block"|"redirect"|"pass", cname_target, a, aaaa, ttl }
classify = (dns, raw, l7_off=1) ->
  return { verdict: "pass" } unless dns and dns.header

  if numeric_rcode(dns.header) == NXDOMAIN
    return { verdict: "block" }

  -- Adresses A/AAAA et TTL minimal de la réponse (réutilisés par sinkhole/redirect).
  a, aaaa, ttl = {}, {}, nil
  for rr in *(dns.answers or {})
    if rr.rtype == A and rr.rdata and #rr.rdata == 4
      a[#a + 1] = rr.rdata
    elseif rr.rtype == AAAA and rr.rdata and #rr.rdata == 16
      aaaa[#aaaa + 1] = rr.rdata
    if rr.ttl and (not ttl or rr.ttl < ttl)
      ttl = rr.ttl

  -- Sinkhole (0.0.0.0 / ::) : signal de blocage de DNSforFamily (NOERROR) ;
  -- on reproduit ces adresses nulles côté client plutôt qu'un NXDOMAIN.
  return { verdict: "sinkhole", :a, :aaaa, :ttl } if is_sinkhole dns

  targets = cname_targets dns, raw, l7_off
  return { verdict: "pass" } if #targets == 0

  {
    verdict: "redirect"
    cname_target: targets[#targets]  -- cible finale de la chaîne
    :a, :aaaa, :ttl
  }

{ :classify, :cname_targets, :has_cname_target, :decode_cname_target, :numeric_rcode, :is_sinkhole, :is_sinkhole_addr }
