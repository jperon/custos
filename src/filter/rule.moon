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
-- @tparam table rule_cfg Table de configuration d'une règle
-- @treturn function compiled_rule (req) → boolean|nil, string
local compile_rule
compile_rule = (cfg, rule_cfg) ->
  -- Compilation des conditions
  conditions = {}
  for name, args in pairs (rule_cfg.conditions or {})
    ok, factory_loader = pcall require, "filter.conditions.#{name}"
    unless ok
      error "Condition inconnue '#{name}': #{factory_loader}"
    factory = factory_loader cfg
    conditions[#conditions + 1] = factory args

  -- Compilation des actions
  actions = {}
  for _, action_name in ipairs (rule_cfg.actions or {})
    ok, factory_loader = pcall require, "filter.actions.#{action_name}"
    unless ok
      error "Action inconnue '#{action_name}': #{factory_loader}"
    actions[#actions + 1] = (factory_loader cfg) rule_cfg

  -- Fonction d'évaluation de la règle
  (req) ->
    -- Vérifier toutes les conditions (ET logique)
    for _, cond in ipairs conditions
      ok, reason = cond req
      return nil, reason unless ok

    -- Toutes les conditions passées : exécuter les actions
    local verdict, msg
    for _, action in ipairs actions
      v, m = action req
      if v ~= nil and verdict == nil
        verdict = v
        msg     = m
      elseif v == nil and m
        -- Action sans verdict (ex. mail) : logué ailleurs
        msg = msg or m

    verdict, msg

--- Compile une liste ordonnée de règles.
-- @tparam table cfg          Configuration globale du filtre
-- @tparam table rules_cfg    Table de configurations de règles (tableau ordonné)
-- @treturn table             Tableau de fonctions compilées
compile_rules = (cfg) ->
  rules = {}
  for _, rule_cfg in ipairs (cfg.rules or {})
    rules[#rules + 1] = compile_rule cfg, rule_cfg
  rules

--- Évalue les règles dans l'ordre et retourne le premier verdict.
-- Si aucune règle ne correspond, retourne false (deny par défaut).
-- @tparam table  rules Résultat de compile_rules
-- @tparam table  req   {domain, src_ip, mac, ts, ...}
-- @treturn boolean, string
decide = (rules, req) ->
  for _, rule_fn in ipairs rules
    verdict, msg = rule_fn req
    return verdict, msg if verdict ~= nil
  false, "No matching rule (default deny)"

{ :compile_rules, :decide }
