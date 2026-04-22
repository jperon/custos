-- src/filter/conditions/to_domain.moon
-- Condition : le domaine demandé (ou un de ses ancêtres) correspond
-- exactement à la valeur configurée.
-- Supporte les valeurs spéciales `_any` (n'importe quel domaine)
-- et `_none` (aucun domaine).
-- Port direct de shelterfilter conditions/to_domain.moon.

--- @tparam table cfg Configuration du filtre (non utilisée ici)
-- @treturn function factory (domain) → (req) → bool, reason
(cfg) -> (domain) ->
  if domain == "_any"
    return (req) -> req.domain ~= nil, "domain available"
  if domain == "_none"
    return (req) -> req.domain == nil, "domain not available"

  --- @tparam table req {domain: string, ...}
  -- @treturn boolean, string
  (req) ->
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
