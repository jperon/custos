-- src/filter/actions/log.moon
-- Action : Log des informations sur la requête et/ou la règle.

log = require "log"

-- Factory function for the action, convention (cfg) -> (rule) -> (req).
-- Le message vient de rule.log.log_msg (forme table `{ log: { log_msg } }`
-- écrite par la webui) s'il est une chaîne non vide.
_schema = {
  label:       "Journaliser"
  description: "Enregistre un message de log sans prendre de décision (verdict nil)"
  arg_type:    "table"
  arg_fields:  { { name: "log_msg", label: "Message", type: "string", required: false } }
}

_factory = (cfg) ->
  (rule) ->
    log_message = "Log action triggered by rule"
    if rule.log and type(rule.log.log_msg) == "string" and rule.log.log_msg != ""
      log_message = rule.log.log_msg

    -- Return the actual action function that will be executed per request.
    (req) ->
      log_fields = {}
      log_fields.action = "log_action"
      log_fields.requested_domain = req.domain
      log_fields.requested_ip = req.src_ip
      log_fields.requested_mac = req.mac
      log_fields.message = log_message

      if rule.description
        log_fields.rule_description = rule.description

      log.log_info -> log_fields

      -- Effet de bord pur : verdict nil, l'évaluation continue.
      nil, log_message

{ schema: _schema, factory: _factory }
