local log = require("log")
return function(cfg, rule_cfg)
  local log_message = "Log action triggered by rule"
  if rule_cfg.log_msg then
    log_message = rule_cfg.log_msg
  end
  return function(req)
    local log_fields = { }
    log_fields.action = "log_action"
    log_fields.requested_domain = req.domain
    log_fields.requested_ip = req.src_ip
    log_fields.requested_mac = req.mac
    log_fields.message = log_message
    if rule_cfg.description then
      log_fields.rule_description = rule_cfg.description
    end
    log.log_info(log_fields)
    return nil, log_message
  end
end
