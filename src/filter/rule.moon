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
compile_rule = (cfg, rule, idx) ->
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

  -- Métadonnées de règle propagées au pipeline IPC/NFT.
  rule_desc = rule.description or "rule_#{idx}"
  rule_id = rule.rule_id or "rule_#{idx}"
  rule_timeout = rule.nft_timeout or (cfg.nft and cfg.nft.ip_timeout) or "2m"

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

    verdict, msg, rule_id, rule_timeout, rule_desc

details_of = (rules, req, decision_cfg=nil) ->
  effective_cfg = decision_cfg or (rules and rules.decision_cfg) or {}
  continue_mode = effective_cfg.continue_to_next_rule
  first_match_wins = true
  if effective_cfg.first_match_wins != nil
    first_match_wins = not not effective_cfg.first_match_wins

  last_verdict, last_msg, last_rule_id, last_timeout, last_rule_desc = nil, nil, nil, nil, nil
  for rule_fn in *rules
    verdict, msg, rule_id, rule_timeout, rule_desc = rule_fn req
    if verdict ~= nil
      if continue_mode or not first_match_wins
        last_verdict, last_msg, last_rule_id, last_timeout, last_rule_desc = verdict, msg, rule_id, rule_timeout, rule_desc
      else
        return verdict, msg, rule_id, rule_timeout, rule_desc
  if last_verdict ~= nil
    return last_verdict, last_msg, last_rule_id, last_timeout, last_rule_desc
  false, "No matching rule (default deny)", nil, nil, nil

--- Compile une liste ordonnée de règles.
-- @tparam table cfg          Configuration globale du filtre
-- @tparam table rules_cfg    Table de configurations de règles (tableau ordonné)
-- @treturn table             Tableau de fonctions compilées
compile_rules = (cfg) ->
  rules_cfg = cfg.rules or {}
  out = {}
  for idx, rule in ipairs rules_cfg
    out[#out + 1] = compile_rule cfg, rule, idx
  out.decision_cfg = cfg.decision or {}
  out

--- Évalue les règles dans l'ordre et retourne le premier verdict.
-- Si aucune règle ne correspond, retourne false (deny par défaut).
-- @tparam table  rules Résultat de compile_rules
-- @tparam table  req   {domain, src_ip, mac, ts, ...}
-- @tparam table|nil decision_cfg {first_match_wins, continue_to_next_rule}
-- @treturn boolean, string, string|nil, string|nil, string|nil
decide = (rules, req, decision_cfg=nil) ->
  verdict, msg, _, _, rule_desc = details_of rules, req, decision_cfg
  verdict, msg, rule_desc

decide_meta = (rules, req, decision_cfg=nil) ->
  verdict, msg, rule_id, rule_timeout, rule_desc = details_of rules, req, decision_cfg
  {
    verdict: verdict
    reason: msg
    rule_id: rule_id
    timeout: rule_timeout
    description: rule_desc
  }

{ :compile_rules, :decide, :decide_meta }
