-- src/filter/conditions/to_domains.moon
-- Condition : le domaine demandé correspond à l'un des domaines listés.
-- API enrichie : worker-only (DNS matching).
--
-- Le nom est cherché dans un index construit à la compilation (ensemble des
-- domaines de la liste), en testant le nom exact puis chacun de ses suffixes
-- après un point — comme `to_domainlist` (cf. `to_domainlist.moon:174-186`).
-- Le coût par requête suit donc le nombre de labels du nom, pas la taille de la
-- liste : la liste SafeSearch Google (194 domaines) coûtait ~3,5 µs/requête en
-- parcourant toutes ses entrées (cf. docs/agents/perf.md §29c).
--
-- Sémantique d'un match (identique à `to_domain`) : « Exact match » si le nom
-- entier est dans la liste, « Subdomain matched » sinon. Si la liste contient
-- à la fois un nom et l'un de ses parents, c'est le message « Exact match » qui
-- est rendu (auparavant, l'ordre de la liste décidait du message ; le verdict,
-- lui, est le même).

--- @tparam table cfg Configuration
-- @treturn function factory (domains) → enriched_condition
_schema = {
  label:       "Domaines cibles"
  description: "Domaine correspondant à l'un des domaines de la liste"
  category:    "destination"
  arg_type:    "string_list"
}

_factory = (cfg) ->
  to_domain_factory = (require "filter.conditions.to_domain").factory
  (domains) ->
    domain_list = domains
    unless type(domains) == "table"
      domain_list = { domains }

    -- Index des domaines de la liste. Les valeurs spéciales `_any`/`_none`
    -- (cf. to_domain) ne sont pas des noms : elles restent des conditions
    -- dédiées, évaluées d'abord.
    domain_set = {}
    special_conds = {}
    for _, d in ipairs domain_list
      if d == "_any" or d == "_none"
        special_conds[#special_conds + 1] = to_domain_factory(cfg)(d)
      else
        domain_set[d] = true

    {
      capabilities: { worker: true, nft: false, nft_dynamic: false }
      domains: domain_list
      eval: (req) ->
        for _, special in ipairs special_conds
          ok, msg = special.eval req
          return ok, msg if ok

        _domain = req.domain
        return false, "Not matched by any domain" unless _domain
        return true, "Exact match" if domain_set[_domain]

        pos = _domain\find ".", 1, true
        while pos
          return true, "Subdomain matched" if domain_set[_domain\sub pos + 1]
          pos = _domain\find ".", pos + 1, true

        false, "Not matched by any domain"
      creates_dynamic_scope: true
    }

{ schema: _schema, factory: _factory }
