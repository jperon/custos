-- src/filter/conditions/_match_int.moon
-- Condition abstraite : vérifie si un champ entier correspond à une valeur.
--- @tparam string prop Nom de la propriété dans req (ex. "vlan")
-- @treturn function factory (cfg) → (val) → (req) → bool
(prop) ->
  (cfg) -> (val) ->
    --- @tparam table req {vlan: number, ...}
    -- @treturn boolean, string
    (req) ->
      _val = req[prop]
      return false, "#{prop} not available in request" unless _val
      _val == val, "#{prop} #{_val} vs #{val}"
