-- src/filter/actions/allow_ip4.moon
-- Action : autoriser la requête mais ne conserver que les enregistrements A (IPv4)
-- dans la réponse DNS (les AAAA sont stripés). Les IPs résolues sont injectées
-- normalement dans les sets nft.
-- API enrichie : worker-only (pas de compilation nft possible).
--
-- Retourne "allow_ip4" (valeur truthy distincte de `true` et "dnsonly").
-- Le worker question la traite via write_allow_ip4_msg ; response strip les AAAA
-- du payload DNS et ajoute EDE code 4 (Forged Answer).

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (rule) → enriched_action
(cfg) ->
  (rule) ->
    {
      capabilities: { worker: true, nft: false }
      eval: (req) ->
        "allow_ip4", "Allow IPv4 only by rule: #{rule.description or '?' }"
      compile_nft: ->
      verdict: ->
        "allow_ip4"
    }
