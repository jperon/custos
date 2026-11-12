-- src/second_opinion.moon
-- État du « second avis » côté worker_responses : ensemble des IP validateur,
-- stockage des verdicts en attente de corrélation, et table des réponses
-- d'origine (A) parquées en attendant le verdict du validateur (B).
--
-- Logique pure et testable (aucun effet de bord NFQUEUE) : worker_responses
-- fournit le temps courant et exécute les actions de relâche/expiration.
--
-- Corrélation par clé (client_ip, txid, qname) : identique pour A et B car la
-- question est dupliquée à l'identique vers le validateur.

{ :concat } = table

{ :to_hex, :from_hex, :split_fields, :is_ipv4_str, :is_ipv6_str } = require "lib.ipc_hex"

-- ── Bus inter-workers ────────────────────────────────────────────────────────
-- Avec plusieurs workers réponses (`nfqueue.responses` = plage), la réponse
-- d'origine (A, client↔résolveur) et celle du validateur (B, client↔validateur)
-- ont des couples d'adresses différents : le hachage de flux du noyau les
-- distribue sur des files distinctes (hash_v4 trie saddr/daddr, sans les ports,
-- cf. include/net/netfilter/nf_queue.h). Le verdict B est donc diffusé à tous
-- les workers par un pipe dédié à chacun (fan-out), encodé ici en une ligne
-- texte versionnée de taille bornée (< PIPE_BUF : écriture atomique).
VERDICT_PREFIX = "v1"
MAX_VERDICT_LINE = 2048
MAX_VERDICT_ADDRS = 16

_KIND_TO_CODE = { block: "b", sinkhole: "s", redirect: "r", pass: "p" }
_CODE_TO_KIND = { b: "block", s: "sinkhole", r: "redirect", p: "pass" }

--- Encode une liste d'adresses (rdata brutes) en CSV hexadécimal borné.
-- @tparam table|nil list Adresses brutes (4 ou 16 octets)
-- @treturn string CSV ("" si vide)
_encode_addrs = (list) ->
  parts = {}
  for r in *(list or {})
    break if #parts >= MAX_VERDICT_ADDRS
    continue unless r and (#r == 4 or #r == 16)
    parts[#parts + 1] = to_hex r
  concat parts, ","

--- Décode une liste d'adresses CSV hexadécimal.
-- @tparam string|nil s CSV
-- @tparam number want_len Longueur attendue d'une adresse (4 ou 16)
-- @treturn table|nil Liste d'adresses brutes
-- @treturn string|nil Code d'erreur
_decode_addrs = (s, want_len) ->
  out = {}
  return out, nil unless s and s != ""
  for h in s\gmatch "[^,]+"
    raw, err = from_hex h
    return nil, "addr_#{err}" if err
    return nil, "addr_len" unless #raw == want_len
    out[#out + 1] = raw
  out, nil

--- Encode un verdict B pour le bus inter-workers (fonction pure).
-- @tparam string client_ip IP du client (dst de la réponse B)
-- @tparam number txid      ID de transaction DNS
-- @tparam string qname     Nom de la question (casse préservée, comparée en
--                          minuscules par `corr_key`)
-- @tparam table  override  Verdict de `make_override` (worker_responses)
-- @treturn string|nil Ligne terminée par \n, ou nil si inencodable (le verdict
--                     sera alors perdu : la réponse A expirera en fail-open)
encode_verdict = (client_ip, txid, qname, override) ->
  return nil unless client_ip and override
  code = _KIND_TO_CODE[override.kind]
  return nil unless code
  ttl = tonumber override.ttl
  line = concat {
    VERDICT_PREFIX
    code
    tostring client_ip
    string.format "%04x", tonumber(txid) or 0
    tostring(ttl and math.floor(ttl) or -1)
    to_hex tostring(qname or "")
    to_hex tostring(override.cname_target or "")
    _encode_addrs override.a
    _encode_addrs override.aaaa
  }, "|"
  return nil if #line > MAX_VERDICT_LINE
  line .. "\n"

--- Décode une ligne du bus inter-workers (fonction pure).
-- @tparam string line Ligne encodée (sans ou avec \n final)
-- @treturn table|nil { client_ip, txid, qname, override }
-- @treturn string|nil Code d'erreur
decode_verdict = (line) ->
  s = (tostring line)\gsub "\n+$", ""
  parts = split_fields s
  return nil, "field_count" unless #parts == 9
  return nil, "version" unless parts[1] == VERDICT_PREFIX
  kind = _CODE_TO_KIND[parts[2]]
  return nil, "kind" unless kind
  client_ip = parts[3]
  return nil, "client_ip" unless is_ipv4_str(client_ip) or is_ipv6_str(client_ip)
  txid = tonumber parts[4], 16
  return nil, "txid" unless txid and txid >= 0 and txid <= 65535
  ttl = tonumber parts[5]
  return nil, "ttl" unless ttl
  qname, e1 = from_hex parts[6]
  return nil, "qname_#{e1}" if e1
  cname, e2 = from_hex parts[7]
  return nil, "cname_#{e2}" if e2
  a, e3 = _decode_addrs parts[8], 4
  return nil, "a_#{e3}" if e3
  aaaa, e4 = _decode_addrs parts[9], 16
  return nil, "aaaa_#{e4}" if e4
  {
    client_ip: client_ip
    txid: txid
    qname: qname or ""
    override: {
      :kind
      :a, :aaaa
      ttl: (ttl >= 0 and ttl or nil)
      cname_target: (cname and cname != "") and cname or nil
    }
  }, nil

--- Crée un état second-avis.
-- @tparam[opt] table opts { resolvers, verdict_ttl_s, budget_ms }
-- @treturn table État avec ses méthodes (closures).
new = (opts={}) ->
  resolvers = opts.resolvers or {}
  verdict_ttl = opts.verdict_ttl_s or 5      -- durée de vie d'un verdict orphelin
  budget_ms = opts.budget_ms or 80
  -- Familles pour lesquelles la duplication est effective (gateway dispo).
  -- Une famille inactive ne doit jamais être parquée (sinon latence inutile).
  families = opts.families or { ipv4: true, ipv6: true }

  -- Ensemble des IP validateur (pour identifier la réponse B par src IP).
  validator_set = {}
  validator_set[ip] = true for ip in *resolvers

  verdicts = {}   -- key → { verdict, expires_at }
  parked   = {}   -- key → { ctx, deadline_ms }

  corr_key = (client_ip, txid, qname) ->
    concat { tostring(client_ip), string.format("%04x", txid or 0), (qname or "")\lower! }, "|"

  --- Vrai si `src_ip` est une IP validateur (donc réponse B à intercepter).
  is_validator = (src_ip) -> validator_set[src_ip] == true

  --- Vrai si la famille (4/6) du paquet est dupliquée (donc A doit attendre B).
  active_for = (version) ->
    if version == 6 then families.ipv6 == true else families.ipv4 == true

  --- Mémorise un verdict B en attendant l'arrivée de A.
  store_verdict = (key, verdict, now_s) ->
    verdicts[key] = { :verdict, expires_at: (now_s or 0) + verdict_ttl }

  --- Récupère (et consomme) le verdict B pour `key`, ou nil si absent/expiré.
  take_verdict = (key, now_s) ->
    e = verdicts[key]
    return nil unless e
    verdicts[key] = nil
    return nil if now_s and now_s > e.expires_at
    e.verdict

  --- Parque la réponse d'origine A en attendant B (deadline = now + budget).
  park = (key, ctx, now_ms) ->
    parked[key] = { :ctx, deadline_ms: (now_ms or 0) + budget_ms }

  --- Récupère (et retire) une réponse A parquée pour `key`, ou nil.
  take_parked = (key) ->
    e = parked[key]
    return nil unless e
    parked[key] = nil
    e.ctx

  --- Retire et renvoie les contextes A dont le budget est dépassé.
  -- @tparam number now_ms Temps courant (ms monotone).
  -- @treturn table Liste de ctx à relâcher en fail-open.
  expired = (now_ms) ->
    out = {}
    for key, e in pairs parked
      if now_ms >= e.deadline_ms
        out[#out + 1] = e.ctx
        parked[key] = nil
    out

  has_parked = -> next(parked) != nil

  --- Purge les verdicts B expirés jamais consommés par take_verdict (A jamais
  -- arrivé : paquet perdu, client qui abandonne). Sans cet appel périodique,
  -- verdicts ne purge qu'à la lecture et une entrée jamais relue reste en
  -- mémoire indéfiniment.
  -- @tparam number now_s Temps courant (secondes)
  purge_verdicts = (now_s) ->
    for key, e in pairs verdicts
      verdicts[key] = nil if now_s > e.expires_at

  {
    :corr_key, :is_validator, :active_for
    :store_verdict, :take_verdict
    :park, :take_parked, :expired, :has_parked
    :purge_verdicts
    :budget_ms
  }

{ :new, :encode_verdict, :decode_verdict, VERDICT_PREFIX: VERDICT_PREFIX, MAX_VERDICT_LINE: MAX_VERDICT_LINE }
