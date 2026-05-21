local compiler_api = require("filter.compiler_api")
return function(cfg)
  return function(sub_condition_spec)
    if not (type(sub_condition_spec) == "table") then
      return {
        capabilities = {
          worker = true,
          nft = false,
          nft_dynamic = false
        },
        eval = function(req)
          return false, "not requires a single condition table"
        end
      }
    end
    local cond_name, cond_args
    for _name, _args in pairs(sub_condition_spec) do
      cond_name, cond_args = _name, _args
    end
    if not (cond_name) then
      return {
        capabilities = {
          worker = true,
          nft = false,
          nft_dynamic = false
        },
        eval = function(req)
          return false, "not: empty condition table"
        end
      }
    end
    local factory, err = compiler_api.load_condition(cond_name)
    if not (factory) then
      error("not: condition inconnue '" .. tostring(cond_name) .. "': " .. tostring(err))
    end
    local cond_obj = factory(cfg)(cond_args)
    local inner_nft = cond_obj.capabilities and cond_obj.capabilities.nft or false
    return {
      capabilities = {
        worker = true,
        nft = inner_nft,
        nft_dynamic = false
      },
      creates_dynamic_scope = cond_obj.creates_dynamic_scope or false,
      negate_mark = true,
      compile_nft = cond_obj.compile_nft,
      eval = function(req)
        local ok, msg = cond_obj.eval(req)
        if ok == nil then
          return nil, msg
        end
        if ok then
          return false, "not(" .. tostring(cond_name) .. "): matched → negated to false"
        else
          return true, "not(" .. tostring(cond_name) .. "): unmatched → negated to true"
        end
      end
    }
  end
end
