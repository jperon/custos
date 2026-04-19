-- src/filter/conditions/_match_intlist.moon
-- Condition abstraite : vérifie si un champ entier appartient à une liste nommée.
--- @tparam string prop Nom de la propriété dans req (ex. "vlan")
-- @treturn function factory (cfg) → (list_name) → (req) → bool
(prop) ->
  (cfg) -> (list_name) ->
    --- @tparam table req {vlan: number, ...}
    -- @treturn boolean, string
    (req) ->
      _val = req[prop]
      return false, "#{prop} not available in request" unless _val

      target_list = cfg.lists and cfg.lists[list_name] or {}
      for _, v in ipairs target_list
        return true, nil if v == _val

      false, "#{prop} #{_val} not in list #{list_name}"
