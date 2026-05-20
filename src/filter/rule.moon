-- src/filter/rule.moon
-- Compilation et évaluation des règles du filtre.
--
-- Une règle est un triplet (conditions, actions, métadonnées) :
--   • Conditions : ET logique implicite — toutes doivent passer.
--   • Actions    : la première qui retourne un verdict non-nil (true/false) gagne.
--                  Une action retournant nil est un effet de bord pur (log, mail…)
--                  et laisse l'évaluation continuer aux règles suivantes.
--   • on_response: callbacks statiques des actions, stockés dans les métadonnées
--                  et appelés par worker_responses via filter.get_rule_on_response.
--                  Le moteur les collecte sans en connaître la sémantique.

compiler_api = require "filter.compiler_api"

--- Compile une règle depuis sa table de configuration.
-- @tparam table cfg     Configuration globale du filtre
-- @tparam table rule    Table de configuration d'une règle
-- @tparam number idx    Index de la règle (pour rule_id implicite)
-- @treturn function compiled_rule (req) → verdict, msg, rule_id, timeout, desc
-- @treturn table metadata Métadonnées pour compilation nft
compile_rule = (cfg, rule, idx, used_ids=nil) ->
  conditions_eval = {}
  conditions_meta = {}
  condition_table = rule.conditions or {}

  unless type(condition_table) == "table"
    error "Conditions doit être une table, got #{type(condition_table)}"

  for name, args in pairs condition_table
    cond_factory, err = compiler_api.load_condition name
    error "Condition inconnue '#{name}': #{err}" unless cond_factory

    cond_obj = cond_factory(cfg)(args)
    conditions_eval[#conditions_eval + 1] = cond_obj.eval
    conditions_meta[#conditions_meta + 1] = {
      name:                name
      args:                args
      capabilities:        cond_obj.capabilities
      worker_only:         compiler_api.compute_worker_only(cond_obj)
      compile_nft:         cond_obj.compile_nft
      creates_dynamic_scope: cond_obj.creates_dynamic_scope
    }

  -- Compilation des actions : on stocke eval et on_response séparément.
  -- on_response est un callback statique appelé par worker_responses ; le moteur
  -- l'accumule dans les métadonnées sans en interpréter le contenu.
  action_evals = {}
  actions_meta = {}
  for action_name in *(rule.actions or {})
    action_factory, err = compiler_api.load_action action_name
    error "Action inconnue '#{action_name}': #{err}" unless action_factory

    action_obj = action_factory(cfg)(rule)
    action_evals[#action_evals + 1] = action_obj.eval
    actions_meta[#actions_meta + 1] = {
      name:         action_name
      capabilities: action_obj.capabilities
      worker_only:  compiler_api.compute_worker_only(action_obj)
      compile_nft:  action_obj.compile_nft
      verdict:      action_obj.verdict
      on_response:  action_obj.on_response
    }

  rule_desc    = rule.description or "rule_#{idx}"
  rule_id      = compiler_api.unique_rule_id rule, idx, used_ids
  rule_timeout = rule.nft_timeout or (cfg.nft and cfg.nft.ip_timeout) or "2m"

  -- Liste plate des on_response non-nil pour lookup O(1) depuis worker_responses.
  on_response_list = [am.on_response for am in *actions_meta when am.on_response]

  metadata = {
    rule_id:     rule_id
    description: rule_desc
    timeout:     rule_timeout
    conditions:  conditions_meta
    actions:     actions_meta
    on_response: on_response_list
    worker_only: false
  }

  for cond in *conditions_meta
    if cond.worker_only
      metadata.worker_only = true
      break
  unless metadata.worker_only
    for act in *actions_meta
      if act.worker_only
        metadata.worker_only = true
        break

  metadata.creates_dynamic_scope = false
  for cond_meta in *conditions_meta
    if cond_meta.creates_dynamic_scope
      metadata.creates_dynamic_scope = true
      break

  -- Fonction d'évaluation : premier verdict non-nil gagne.
  -- Une action retournant nil (log, mail, etc.) est un effet de bord pur :
  -- elle n'interrompt pas l'évaluation des règles suivantes.
  eval_fn = (req) ->
    all_passed = true
    for cond in *conditions_eval
      ok, _ = cond req
      unless ok
        all_passed = false
        break

    return nil, "No condition matched" unless all_passed

    local verdict, msg
    for action_eval in *action_evals
      v, m = action_eval req
      if v ~= nil and verdict == nil
        verdict = v
        msg     = m or msg
      elseif v == nil and m
        msg = msg or m

    verdict, msg, rule_id, rule_timeout, rule_desc

  eval_fn, metadata

details_of = (rules, req, decision_cfg=nil) ->
  effective_cfg   = decision_cfg or (rules and rules.decision_cfg) or {}
  continue_mode   = effective_cfg.continue_to_next_rule
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
compile_rules = (cfg) ->
  rules_cfg = cfg.rules or {}
  out = {}
  out.rules_metadata = {}
  used_ids = {}
  for idx, rule in ipairs rules_cfg
    eval_fn, metadata = compile_rule cfg, rule, idx, used_ids
    out[#out + 1] = eval_fn
    out.rules_metadata[idx] = metadata
  out.decision_cfg = cfg.decision or {}
  out

decide = (rules, req, decision_cfg=nil) ->
  verdict, msg, _, _, rule_desc = details_of rules, req, decision_cfg
  verdict, msg, rule_desc

decide_meta = (rules, req, decision_cfg=nil) ->
  verdict, msg, rule_id, rule_timeout, rule_desc = details_of rules, req, decision_cfg
  {
    verdict:     verdict
    reason:      msg
    rule_id:     rule_id
    timeout:     rule_timeout
    description: rule_desc
  }

{ :compile_rule, :compile_rules, :decide, :decide_meta }
