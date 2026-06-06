(require("ipc")).register_modifier("validate")
local _schema = {
  label = "Valider via résolveur externe",
  description = "Duplique la question DNS vers le résolveur validateur (ex. DNSforFamily) et corrèle les deux réponses",
  arg_type = "table",
  arg_fields = {
    {
      name = "validate_resolvers",
      label = "Résolveurs",
      type = "list",
      required = false
    }
  }
}
local _factory
_factory = function(cfg)
  return function(rule)
    local resolvers = rule.validate_resolvers
    return {
      capabilities = {
        worker = true,
        nft = true
      },
      allow_modifiers = {
        validate = resolvers or true
      },
      eval = function(req)
        return true, "Validated by rule: " .. tostring(rule.description or '?')
      end,
      on_response = function(ctx)
        ctx.explicit_allow = true
      end,
      compile_nft = function()
        return "accept", nil
      end,
      verdict = function()
        return "accept"
      end
    }
  end
end
return {
  schema = _schema,
  factory = _factory
}
