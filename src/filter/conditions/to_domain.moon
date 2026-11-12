-- src/filter/conditions/to_domain.moon
-- Condition : le domaine demandé (ou un de ses ancêtres) correspond
-- exactement à la valeur configurée.
-- API enrichie : worker-only (DNS matching requires NFQUEUE).
-- Supporte les valeurs spéciales `_any` et `_none`.

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (domain) → enriched_condition
_schema = {
  label:       "Domaine cible"
  description: "Domaine DNS exact (inclut tous les sous-domaines)"
  category:    "destination"
  arg_type:    "string"
  arg_hint:    "ex: example.com"
}

_factory = (cfg) ->
  (domain) ->
    if domain == "_any"
      return {
        capabilities: { worker: true, nft: false, nft_dynamic: false }
        creates_dynamic_scope: true
        domain: domain
        eval: (req) -> req.domain ~= nil, "domain available"
      }
    if domain == "_none"
      return {
        capabilities: { worker: true, nft: false, nft_dynamic: false }
        domain: domain
        eval: (req) -> req.domain == nil, "domain not available"
      }

    -- Dernier octet du domaine cible, calculé une fois par condition : tout
    -- suffixe d'un nom se termine par le dernier octet de ce nom, donc si les
    -- deux derniers octets diffèrent aucun suffixe ne peut être égal — rejet
    -- O(1) sans allocation (cf. docs/agents/perf.md §18 : les boucles de
    -- suffixes des dizaines de conditions par question coûtaient ~25 % du
    -- chemin question).
    last_byte = #domain > 0 and domain\byte(#domain) or nil

    {
      capabilities: { worker: true, nft: false, nft_dynamic: false }
      creates_dynamic_scope: true
      domain: domain
      eval: (req) ->
        _domain = req.domain
        return false, "Domain not in request" unless _domain
        return true, "Exact match" if _domain == domain

        if last_byte
          return false, "Domain not matched" unless _domain\byte(#_domain) == last_byte

        -- Teste chaque suffixe (labels de droite à gauche) SANS allouer la
        -- sous-chaîne : longueur égale + `find` littéral à la position du
        -- point ⟺ le suffixe vaut exactement `domain`.
        dlen = #_domain
        elen = #domain
        pos = _domain\find ".", 1, true
        while pos
          if dlen - pos == elen and _domain\find(domain, pos + 1, true) == pos + 1
            return true, "Subdomain matched"
          pos = _domain\find ".", pos + 1, true

        false, "Domain not matched"
    }

{ schema: _schema, factory: _factory }
