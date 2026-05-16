-- src/filter/actions/allow_ip6.moon
-- Action : autoriser la requête mais ne conserver que les enregistrements AAAA (IPv6)
-- dans la réponse DNS (les A sont stripés). Les IPs résolues sont injectées
-- normalement dans les sets nft.
-- API enrichie : worker-only (pas de compilation nft possible).
--
-- Retourne "allow_ip6" (valeur truthy distincte de `true` et "dnsonly").
-- Le worker question la traite via write_allow_ip6_msg ; response strip les A
-- du payload DNS et ajoute EDE code 4 (Forged Answer).

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (rule) → enriched_action
(cfg) ->
  (rule) ->
    {
      capabilities: { worker: true, nft: false }
      eval: (req) ->
        "allow_ip6", "Allow IPv6 only by rule: #{rule.description or '?' }"
      compile_nft: ->
      verdict: ->
        "allow_ip6"
    }
