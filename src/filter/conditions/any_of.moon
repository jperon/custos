-- src/filter/conditions/any_of.moon
-- Méta-condition : OU logique entre conditions hétérogènes.
-- Retourne true dès qu'une sous-condition passe.
--
-- Usage config :
--   conditions: { any_of: [{ from_net: "10.0.0.0/8" }, { from_mac: "aa:bb:..." }] }

compiler_api = require "filter.compiler_api"

--- @tparam table cfg Configuration
-- @treturn function factory (sub_conditions) → enriched_condition
(cfg) ->
  (sub_conditions) ->
    unless type(sub_conditions) == "table" and #sub_conditions > 0
      return {
        capabilities: { worker: true, nft: false, nft_dynamic: false }
        eval: (req) -> false, "any_of requires a non-empty table of conditions"
      }

    -- Pré-compiler toutes les sous-conditions à l'init
    compiled = {}
    has_dynamic_scope = false
    for _, cond_spec in ipairs sub_conditions
      local name, args
      if type(cond_spec) == "table"
        for _name, _args in pairs cond_spec
          name, args = _name, _args
      else
        name = cond_spec

      factory, err = compiler_api.load_condition name
      error "any_of: condition inconnue '#{name}': #{err}" unless factory

      cond_obj = factory(cfg)(args)
      compiled[#compiled + 1] = cond_obj
      has_dynamic_scope = true if cond_obj.creates_dynamic_scope

    {
      capabilities: { worker: true, nft: false, nft_dynamic: false }
      creates_dynamic_scope: has_dynamic_scope
      eval: (req) ->
        for _, cond in ipairs compiled
          ok, msg = cond.eval req
          return true, msg if ok
        false, "No sub-condition matched in any_of"
    }
