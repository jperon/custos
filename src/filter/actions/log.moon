-- src/filter/actions/log.moon
-- Action : Log des informations sur la requête et/ou la règle.

log = require "log"

-- Factory function for the action.
-- cfg: global filter configuration.
-- rule_cfg: configuration for this specific rule. The action factory receives the entire rule configuration.
_schema = {
  label:       "Journaliser"
  description: "Enregistre un message de log sans prendre de décision (verdict nil)"
  arg_type:    "table"
  arg_fields:  { { name: "log_msg", label: "Message", type: "string", required: false } }
}

_factory = (cfg, rule_cfg) ->
  -- Extract log message from rule_cfg.log.log_msg if present.
  -- Default message if not found.
  log_message = "Log action triggered by rule"
  if rule_cfg.log_msg
    log_message = rule_cfg.log_msg

  -- Return the actual action function that will be executed per request.
  (req) ->
    -- Log relevant details from the request and rule.
    -- The 'action' field in the log will be 'log_action'.

    -- Prepare a base table for logging fields.
    log_fields = {}
    log_fields.action = "log_action"
    log_fields.requested_domain = req.domain
    log_fields.requested_ip = req.src_ip
    log_fields.requested_mac = req.mac
    log_fields.message = log_message

    -- Add rule description only if it exists.
    if rule_cfg.description
      log_fields.rule_description = rule_cfg.description

    log.log_info(log_fields)

    -- This action does not make a decision (allow/deny).
    -- It returns nil, so other actions or rules can still be evaluated.
    nil, log_message

{ schema: _schema, factory: _factory }
