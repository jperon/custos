-- src/filter/conditions/not.moon
-- Méta-condition : négation logique d'une condition imbriquée.
-- Retourne l'inverse du résultat de la sous-condition.
-- nil (indéterminé) est passé tel quel sans inversion.
--
-- Usage config :
--   conditions: { not: { from_vlan: 1 } }

compiler_api = require "filter.compiler_api"

_schema = {
  label:       "NON logique"
  description: "Inverse le résultat d'une sous-condition"
  category:    "meta"
  arg_type:    "condition"
}

_factory = (cfg) ->
  (sub_condition_spec) ->
    unless type(sub_condition_spec) == "table"
      return {
        capabilities: { worker: true, nft: false, nft_dynamic: false }
        eval: (req) -> false, "not requires a single condition table"
      }

    local cond_name, cond_args
    for _name, _args in pairs sub_condition_spec
      cond_name, cond_args = _name, _args

    unless cond_name
      return {
        capabilities: { worker: true, nft: false, nft_dynamic: false }
        eval: (req) -> false, "not: empty condition table"
      }

    factory, err = compiler_api.load_condition cond_name
    error "not: condition inconnue '#{cond_name}': #{err}" unless factory

    cond_obj = factory(cfg)(cond_args)
    inner_nft = cond_obj.capabilities and cond_obj.capabilities.nft or false

    {
      capabilities: { worker: true, nft: inner_nft, nft_dynamic: false }
      creates_dynamic_scope: cond_obj.creates_dynamic_scope or false
      negate_mark: true
      compile_nft: cond_obj.compile_nft
      eval: (req) ->
        ok, msg = cond_obj.eval req
        return nil, msg if ok == nil
        if ok
          false, "not(#{cond_name}): matched → negated to false"
        else
          true, "not(#{cond_name}): unmatched → negated to true"
    }

{ schema: _schema, factory: _factory }
