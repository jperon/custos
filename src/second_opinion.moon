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

  {
    :corr_key, :is_validator, :active_for
    :store_verdict, :take_verdict
    :park, :take_parked, :expired, :has_parked
    :budget_ms
  }

{ :new }
