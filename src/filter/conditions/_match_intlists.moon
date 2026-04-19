-- src/filter/conditions/_match_intlists.moon
-- Condition abstraite : vérifie si un champ entier appartient à l'une de plusieurs listes.
--- @tparam string prop Nom de la propriété dans req (ex. "vlan")
-- @treturn function factory (cfg) → (list_names) → (req) → bool
(prop) ->
  (cfg) -> (list_names) ->
    unless type list_names == "table"
      error "list_names must be a table of list names"

    -- DRY : on compose à partir de _match_intlist
    _match_intlist = require "filter.conditions._match_intlist"
    match_fn = _match_intlist prop cfg

    --- @tparam table req {vlan: number, ...}
    -- @treturn boolean, string
    (req) ->
      for _, name in ipairs list_names
        ok, reason = _match_intlist name req
        return true, reason if ok

      false, "#{prop} not in any of the specified lists"
