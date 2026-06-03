(require("ipc")).register_modifier("unconditionally_allow")
local _schema = {
  label = "Autoriser sans validateur",
  description = "Autorise la requête DNS sans duplication vers le résolveur validateur",
  arg_type = nil
}
local _factory
_factory = function(cfg)
  return function(rule)
    return {
      capabilities = {
        worker = true,
        nft = true
      },
      allow_modifiers = {
        unconditionally_allow = true
      },
      eval = function(req)
        return true, "Unconditionally allowed by rule: " .. tostring(rule.description or '?')
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
