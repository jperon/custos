-- src/filter/conditions/from_vlans.moon
-- Condition : le VLAN source appartient à un ensemble défini inline.
-- Nous détournons _match_intlist en passant une table comme list_name (le moteur filter.rule gère l'appel).

(cfg) -> (val) ->
  unless type val == "table"
    error "from_vlans requires a table of integers"
  
  (req) ->
    _val = req.vlan
    return false, "vlan not available in request" unless _val
    for _, v in ipairs val
      return true, nil if v == _val
    false, "vlan #{_val} not in list"
