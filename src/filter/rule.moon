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

compiler_api = require "filter.compiler_api"

--- Compile une règle depuis sa table de configuration.
-- Supporte les modules ancien style (factory function) et nouveau style
-- (API enrichie avec capabilities/compile_nft).
-- @tparam table cfg     Configuration globale du filtre
-- @tparam table rule    Table de configuration d'une règle
-- @tparam number idx    Index de la règle (pour rule_id implicite)
-- @treturn function compiled_rule (req) → verdict, msg, rule_id, timeout, desc
-- @treturn table metadata Métadonnées pour compilation nft
compile_rule = (cfg, rule, idx) ->
  -- Compilation des conditions avec adaptation API
  conditions = {}
  conditions_meta = {}
  for condition in *(rule.conditions or {})
    name, args = nil, nil
    if type(condition) == "table"
      for _name, _args in pairs condition
        name, args = _name, _args
    else
      name = condition
    
    cond_factory, err = compiler_api.load_condition name
    error "Condition inconnue '#{name}': #{err}" unless cond_factory
    
    cond_obj = cond_factory(cfg)(args)
    conditions[#conditions + 1] = cond_obj.eval
    conditions_meta[#conditions_meta + 1] = {
      name: name
      args: args
      capabilities: cond_obj.capabilities
      worker_only: compiler_api.compute_worker_only(cond_obj)
      compile_nft: cond_obj.compile_nft
      creates_dynamic_scope: cond_obj.creates_dynamic_scope
    }

  -- Compilation des actions avec adaptation API
  actions = {}
  actions_meta = {}
  for action_name in *(rule.actions or {})
    action_factory, err = compiler_api.load_action action_name
    error "Action inconnue '#{action_name}': #{err}" unless action_factory
    
    action_obj = action_factory(cfg)(rule)
    actions[#actions + 1] = action_obj.eval
    actions_meta[#actions_meta + 1] = {
      name: action_name
      capabilities: action_obj.capabilities
      worker_only: compiler_api.compute_worker_only(action_obj)
      compile_nft: action_obj.compile_nft
      verdict: action_obj.verdict
    }

  -- Métadonnées de règle propagées au pipeline IPC/NFT.
  rule_desc = rule.description or "rule_#{idx}"
  rule_id = rule.rule_id or "rule_#{idx}"
  rule_timeout = rule.nft_timeout or (cfg.nft and cfg.nft.ip_timeout) or "2m"

  -- Métadonnées pour compilation nft
  metadata = {
    rule_id: rule_id
    description: rule_desc
    timeout: rule_timeout
    conditions: conditions_meta
    actions: actions_meta
    worker_only: false
  }

  -- Déterminer si la règle est worker-only (toutes conditions/actions worker-only)
  for cond in *conditions_meta
    if cond.worker_only
      metadata.worker_only = true
      break
  unless metadata.worker_only
    for act in *actions_meta
      if act.worker_only
        metadata.worker_only = true
        break

  -- Déterminer si la règle crée un scope dynamique (DNS)
  metadata.creates_dynamic_scope = false
  for cond in *conditions_meta
    if cond.creates_dynamic_scope
      metadata.creates_dynamic_scope = true
      break

  -- Fonction d'évaluation de la règle
  eval_fn = (req) ->
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

  eval_fn, metadata

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
-- @treturn table             Tableau de fonctions compilées + métadonnées nft
compile_rules = (cfg) ->
  rules_cfg = cfg.rules or {}
  out = {}
  out.rules_metadata = {}
  for idx, rule in ipairs rules_cfg
    eval_fn, metadata = compile_rule cfg, rule, idx
    out[#out + 1] = eval_fn
    out.rules_metadata[idx] = metadata
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

{ :compile_rule, :compile_rules, :decide, :decide_meta }
