local compiler_api = require("filter.compiler_api")
local _schema = {
  label = "OU logique",
  description = "Vrai si au moins une sous-condition est vraie",
  category = "meta",
  arg_type = "condition_list"
}
local _factory
_factory = function(cfg)
  return function(sub_conditions)
    if not (type(sub_conditions) == "table" and #sub_conditions > 0) then
      return {
        capabilities = {
          worker = true,
          nft = false,
          nft_dynamic = false
        },
        eval = function(req)
          return false, "any_of requires a non-empty table of conditions"
        end
      }
    end
    local compiled = { }
    local has_dynamic_scope = false
    for _, cond_spec in ipairs(sub_conditions) do
      local name, args
      if type(cond_spec) == "table" then
        for _name, _args in pairs(cond_spec) do
          name, args = _name, _args
        end
      else
        name = cond_spec
      end
      local factory, err = compiler_api.load_condition(name)
      if not (factory) then
        error("any_of: condition inconnue '" .. tostring(name) .. "': " .. tostring(err))
      end
      local cond_obj = factory(cfg)(args)
      compiled[#compiled + 1] = cond_obj
      if cond_obj.creates_dynamic_scope then
        has_dynamic_scope = true
      end
    end
    return {
      capabilities = {
        worker = true,
        nft = false,
        nft_dynamic = false
      },
      creates_dynamic_scope = has_dynamic_scope,
      eval = function(req)
        for _, cond in ipairs(compiled) do
          local ok, msg = cond.eval(req)
          if ok then
            return true, msg
          end
        end
        return false, "No sub-condition matched in any_of"
      end
    }
  end
end
return {
  schema = _schema,
  factory = _factory
}
