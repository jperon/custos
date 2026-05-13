-- src/filter/conditions/to_domain.moon
-- Condition : le domaine demandé (ou un de ses ancêtres) correspond
-- exactement à la valeur configurée.
-- API enrichie : worker-only (DNS matching requires NFQUEUE).
-- Supporte les valeurs spéciales `_any` et `_none`.

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (domain) → enriched_condition
(cfg) ->
  (domain) ->
    if domain == "_any"
      return {
        capabilities: { worker: true, nft_static: false, nft_dynamic: false }
        worker_only: true
        creates_dynamic_scope: true
        domain: domain
        eval: (req) -> req.domain ~= nil, "domain available"
        compile_nft: -> nil, "to_domain requires worker (DNS)"
      }
    if domain == "_none"
      return {
        capabilities: { worker: true, nft_static: false, nft_dynamic: false }
        worker_only: true
        creates_dynamic_scope: false
        domain: domain
        eval: (req) -> req.domain == nil, "domain not available"
        compile_nft: -> nil, "to_domain requires worker (DNS)"
      }

    {
      capabilities: { worker: true, nft_static: false, nft_dynamic: false }
      worker_only: true
      creates_dynamic_scope: true
      domain: domain
      eval: (req) ->
        _domain = req.domain
        return false, "Domain not in request" unless _domain
        return true, "Exact match" if _domain == domain

        -- Teste chaque suffixe (labels de droite à gauche)
        pos = _domain\find ".", 1, true
        while pos
          suffix = _domain\sub pos + 1
          return true, "Subdomain matched" if suffix == domain
          pos = _domain\find ".", pos + 1, true

        false, "Domain not matched"
      compile_nft: -> nil, "to_domain requires worker (DNS matching)"
    }
