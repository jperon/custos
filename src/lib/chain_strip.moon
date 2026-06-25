-- src/lib/chain_strip.moon
-- Détecte si la feature « strip DNS contextuel à la chaîne CNAME » est
-- active dans la configuration (au moins une règle avec dns_strip.follow_cname).
-- Extrait de main.moon pour rester testable unitairement : `require "main"`
-- exécute des effets de bord au chargement (lecture de config, création de
-- pipes, supervise! en top-level), ce qui rend le module impropre à un
-- require direct dans les specs.

--- Vrai si une règle de config.filter.rules active le strip contextuel CNAME.
-- follow_cname est désormais actif par défaut dès qu'une règle porte dns_strip ;
-- seul follow_cname: false (opt-out explicite) le désactive.
-- @tparam table config Configuration globale (ou nil)
-- @treturn bool
chain_strip_active = (config) ->
  rules = config and config.filter and config.filter.rules
  return false unless type(rules) == "table"
  for r in *rules
    return true if r.dns_strip and r.dns_strip.follow_cname != false
  false

{ :chain_strip_active }
