local _schema = {
  label = "Bloquer",
  description = "Bloque la requête DNS (réponse REFUSED)",
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
      eval = function(req)
        return false, "Denied by rule: " .. tostring(rule.description or '?')
      end,
      compile_nft = function()
        return "drop", nil
      end,
      verdict = function()
        return "drop"
      end
    }
  end
end
return {
  schema = _schema,
  factory = _factory
}
