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
      negate_mark:         cond_obj.negate_mark or false
    }

  -- Compilation des actions : on stocke eval et on_response séparément.
  -- on_response est un callback statique appelé par worker_responses ; le moteur
  -- l'accumule dans les métadonnées sans en interpréter le contenu.
  action_evals = {}
  actions_meta = {}
  rule_block_modifiers = {}
  rule_allow_modifiers = {}
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
    if action_obj.block_modifiers
      for k, v in pairs action_obj.block_modifiers
        rule_block_modifiers[k] = v
    if action_obj.allow_modifiers
      for k, v in pairs action_obj.allow_modifiers
        rule_allow_modifiers[k] = v

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
  }
  -- Affectation hors du littéral : un champ constant `false` dans un table
  -- literal compile en KPRI et échappe au hook de ligne luacov (faux négatif).
  metadata.worker_only = false
  -- Résolveurs per-règle pour l'action validate (second avis DNS).
  -- Stockés dans les métadonnées pour que worker_responses puisse pré-armer so_state.
  if type(rule_allow_modifiers.validate) == "table"
    metadata.validate_resolvers = rule_allow_modifiers.validate

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
  rule_has_on_response = #on_response_list > 0

  eval_fn = (req) ->
    all_passed = true
    condition_reason = nil
    for cond in *conditions_eval
      ok, cond_msg = cond req
      unless ok
        all_passed = false
        break
      if condition_reason == nil and cond_msg
        condition_reason = cond_msg

    return nil, "No condition matched", nil, nil, nil, nil, nil, nil, false, false unless all_passed

    -- Conserver le message de condition pour enrichir les logs (ex: liste matchée).
    req._condition_reason = condition_reason

    local verdict, msg
    for action_eval in *action_evals
      v, m = action_eval req
      if v ~= nil and verdict == nil
        verdict = v
        msg     = m or msg
      elseif v == nil and m
        msg = msg or m

    verdict, msg, rule_id, rule_timeout, rule_desc, rule_block_modifiers, condition_reason, rule_allow_modifiers, true, rule_has_on_response

  eval_fn, metadata

details_of = (rules, req, decision_cfg=nil) ->
  effective_cfg   = decision_cfg or (rules and rules.decision_cfg) or {}
  continue_mode   = effective_cfg.continue_to_next_rule
  first_match_wins = true
  if effective_cfg.first_match_wins != nil
    first_match_wins = not not effective_cfg.first_match_wins

  last_verdict, last_msg, last_rule_id, last_timeout, last_rule_desc, last_modifiers, last_condition_reason, last_allow_modifiers = nil, nil, nil, nil, nil, nil, nil, nil
  response_rule_ids = {}
  for rule_fn in *rules
    verdict, msg, rule_id, rule_timeout, rule_desc, rule_modifiers, condition_reason, allow_modifiers, matched, has_on_response = rule_fn req
    if matched and has_on_response and rule_id
      response_rule_ids[#response_rule_ids + 1] = rule_id
    if verdict ~= nil
      if continue_mode or not first_match_wins
        last_verdict, last_msg, last_rule_id, last_timeout, last_rule_desc, last_modifiers, last_condition_reason, last_allow_modifiers = verdict, msg, rule_id, rule_timeout, rule_desc, rule_modifiers, condition_reason, allow_modifiers
      else
        return verdict, msg, rule_id, rule_timeout, rule_desc, rule_modifiers, condition_reason, allow_modifiers, response_rule_ids
  if last_verdict ~= nil
    return last_verdict, last_msg, last_rule_id, last_timeout, last_rule_desc, last_modifiers, last_condition_reason, last_allow_modifiers, response_rule_ids
  false, "No matching rule (default deny)", nil, nil, nil, nil, nil, nil, response_rule_ids

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
  -- Index rule_id → on_response pour un lookup O(1) depuis worker_responses
  -- (les rule_id sont uniques, garantis par compiler_api.unique_rule_id).
  out.on_response_by_id = {}
  for _, meta in ipairs out.rules_metadata
    out.on_response_by_id[meta.rule_id] = meta.on_response or {}
  out

decide = (rules, req, decision_cfg=nil) ->
  verdict, msg, _, _, rule_desc = details_of rules, req, decision_cfg
  verdict, msg, rule_desc

decide_meta = (rules, req, decision_cfg=nil) ->
  verdict, msg, rule_id, rule_timeout, rule_desc, rule_modifiers, condition_reason, allow_modifiers, response_rule_ids = details_of rules, req, decision_cfg
  {
    verdict:          verdict
    reason:           msg
    condition_reason: condition_reason
    response_rule_ids: response_rule_ids or {}
    rule_id:          rule_id
    timeout:          rule_timeout
    description:      rule_desc
    modifiers:        rule_modifiers or {}
    allow_modifiers:  allow_modifiers or {}
  }

--- Retrouve la liste des callbacks on_response d'une règle (par rule_id).
-- @tparam table  rules   Objet compilé (compile_rules), contient rules_metadata.
-- @tparam string rule_id Identifiant de règle.
-- @treturn table Liste (possiblement vide) de fonctions on_response.
on_response_for = (rules, rule_id) ->
  return {} unless rules and rule_id
  -- Chemin rapide O(1) : map construite par compile_rules.
  if rules.on_response_by_id
    return rules.on_response_by_id[rule_id] or {}
  -- Fallback linéaire (rules assemblés à la main sans la map).
  for _, meta in ipairs (rules.rules_metadata or {})
    if meta.rule_id == rule_id
      return meta.on_response or {}
  {}

on_response_for_many = (rules, rule_ids) ->
  out = {}
  seen = {}
  return out unless rules and type(rule_ids) == "table"
  for _, rid in ipairs rule_ids
    continue if seen[rid]
    seen[rid] = true
    cbs = on_response_for rules, rid
    for cb in *cbs
      out[#out + 1] = cb
  out

--- Applique une liste de callbacks on_response sur une réponse DNS (fonction pure).
-- Noyau commun aux workers (worker_responses, doh) : construit le contexte de
-- réponse, exécute chaque callback (strip DNS, EDE, skip_nft, action_label) puis
-- calcule la décision d'injection nft.
-- `inject_nft = explicit_allow OR (NOT skip_nft)` : "allow" supplante "skip".
-- @tparam table  on_response_cbs Liste de callbacks (peut être vide/nil).
-- @tparam string dns_raw         Réponse DNS brute (wire format).
-- @tparam string reason          Raison de l'autorisation (EDE/log).
-- @tparam table|nil ctx_extra    Champs additionnels injectés dans le contexte.
-- @treturn table Contexte enrichi : { dns_raw, modified, explicit_allow,
--   skip_nft, action_label, reason, inject_nft }.
apply_on_response = (on_response_cbs, dns_raw, reason, ctx_extra=nil) ->
  ctx = {
    dns_raw:        dns_raw
    modified:       false
    explicit_allow: false
    skip_nft:       false
    action_label:   nil
    reason:         reason or ""
  }
  if type(ctx_extra) == "table"
    for k, v in pairs ctx_extra
      ctx[k] = v
  for cb in *(on_response_cbs or {})
    cb ctx
  ctx.inject_nft = ctx.explicit_allow or not ctx.skip_nft
  ctx

--- Dispatch on_response complet : lookup par rule_id puis application.
-- @tparam table  rules   Objet compilé (compile_rules).
-- @tparam string rule_id Identifiant de règle ayant autorisé la requête.
-- @tparam string dns_raw Réponse DNS brute.
-- @tparam string reason  Raison de l'autorisation.
-- @tparam table|nil ctx_extra Champs additionnels injectés dans le contexte.
-- @treturn table Contexte enrichi (cf. apply_on_response).
run_on_response = (rules, rule_id_or_ids, dns_raw, reason, ctx_extra=nil) ->
  callbacks = if type(rule_id_or_ids) == "table"
    on_response_for_many rules, rule_id_or_ids
  else
    on_response_for rules, rule_id_or_ids
  apply_on_response callbacks, dns_raw, reason, ctx_extra

{ :compile_rule, :compile_rules, :decide, :decide_meta, :on_response_for, :apply_on_response, :run_on_response }
