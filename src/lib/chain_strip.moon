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
-- Accepte les deux formes d'action : chaîne "dns_strip" avec options au niveau
-- de la règle (`rule.dns_strip`), et table `{ dns_strip: options }` écrite par
-- la webui (options portées par l'entrée d'action elle-même).
-- @treturn bool
chain_strip_active = (config) ->
  rules = config and config.filter and config.filter.rules
  return false unless type(rules) == "table"
  compiler_api = require "filter.compiler_api"
  for r in *rules
    strip_cfg = r.dns_strip
    for entry in *(r.actions or {})
      if compiler_api.action_name_of(entry) == "dns_strip"
        opts = compiler_api.action_options_of entry
        strip_cfg = opts if opts
    return true if strip_cfg and strip_cfg.follow_cname != false
  false

{ :chain_strip_active }
