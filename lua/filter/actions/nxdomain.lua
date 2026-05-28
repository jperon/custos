(require("ipc")).register_modifier("nxdomain")
local _schema = {
  label = "NXDOMAIN",
  description = "Bloque la requête DNS (réponse NXDOMAIN, sans enregistrement synthétique)",
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
      block_modifiers = {
        nxdomain = true
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
