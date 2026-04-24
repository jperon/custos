-- src/filter/rule.moon
-- Compilation et évaluation des règles du filtre.
--
-- Une règle est un triplet (conditions, actions, métadonnées) :
--   • Conditions : ET logique — toutes doivent passer pour que la règle
--     s'applique. Chaque condition est compilée depuis son module
--     filter.conditions.<name>.
--   • Actions : la première action qui retourne un verdict non-nil donne
--     le résultat (allow=true, deny=false). Les actions suivantes sont
--     ignorées pour le verdict mais peuvent avoir des effets de bord
--     (future : notifications).
--   • Premier verdict gagnant : les règles sont évaluées dans l'ordre ;
--     dès qu'une règle passe, ses actions sont exécutées et on s'arrête.

--- Compile une règle depuis sa table de configuration.
-- @tparam table cfg     Configuration globale du filtre
-- @tparam table rule    Table de configuration d'une règle
-- @treturn function compiled_rule (req) → boolean|nil, string
local compile_rule
compile_rule = (cfg, rule) ->
  -- Compilation des conditions
  conditions = {}
  for condition in *(rule.conditions or {})
    name, args = nil, nil
    if type(condition) == "table"
      for _name, _args in pairs condition
        name, args = _name, _args
    else
      name = condition
    ok, factory_loader = pcall require, "filter.conditions.#{name}"
    error "Condition inconnue '#{name}': #{factory_loader}" unless ok
    factory = factory_loader cfg
    conditions[#conditions + 1] = factory args

  -- Compilation des actions
  actions = {}
  for action in *(rule.actions or {})
    ok, factory_loader = pcall require, "filter.actions.#{action}"
    error "Action inconnue '#{action}': #{factory_loader}" unless ok
    actions[#actions + 1] = (factory_loader cfg) rule

  -- Description humaine ou technique de la règle (pour logs)
  rule_desc = rule.description or rule._desc or rule.name or rule.type

  -- Fonction d'évaluation de la règle
  (req) ->
    -- Vérifier toutes les conditions (ET logique)
    for cond in *conditions
      ok, reason = cond req
      return nil, reason unless ok

    -- Toutes les conditions passées : exécuter les actions
    local verdict, msg
    for action in *actions
      v, m = action req
      -- Premier verdict : mémoriser (peut être false, garder `== nil`)
      if v ~= nil and verdict == nil
        verdict = v
        msg     = m
      elseif v == nil and m
        -- Action sans verdict (ex. mail) : logué ailleurs
        msg = msg or m

    verdict, msg, rule_desc

--- Compile une liste ordonnée de règles.
-- @tparam table cfg          Configuration globale du filtre
-- @tparam table rules_cfg    Table de configurations de règles (tableau ordonné)
-- @treturn table             Tableau de fonctions compilées
compile_rules = (cfg) ->
  [ compile_rule(cfg, rule) for rule in *(cfg.rules or {}) ]

--- Évalue les règles dans l'ordre et retourne le premier verdict.
-- Si aucune règle ne correspond, retourne false (deny par défaut).
-- @tparam table  rules Résultat de compile_rules
-- @tparam table  req   {domain, src_ip, mac, ts, ...}
-- @treturn boolean, string, string
decide = (rules, req) ->
  for rule_fn in *rules
    verdict, msg, rule_desc = rule_fn req
    return verdict, msg, rule_desc if verdict ~= nil
  false, "No matching rule (default deny)", nil

{ :compile_rules, :decide }
