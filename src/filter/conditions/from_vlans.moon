-- src/filter/conditions/from_vlans.moon
-- Condition : le VLAN source appartient à un ensemble défini inline.
-- API enrichie: support nft avec set inline.

--- @tparam table cfg Configuration
-- @treturn function factory (vlan_list) → enriched_condition
(cfg) ->
  (vlan_list) ->
    unless type(vlan_list) == "table"
      return {
        capabilities: { worker: true, nft_static: false, nft_dynamic: false }
        worker_only: true
        eval: (req) -> false, "from_vlans requires a table of integers"
        compile_nft: -> nil, "invalid vlan list"
        creates_dynamic_scope: false
      }
    
    {
      capabilities: { worker: true, nft_static: true, nft_dynamic: false }
      worker_only: false
      vlan_list: vlan_list
      eval: (req) ->
        _val = req.vlan
        return false, "vlan not available" unless _val
        for _, v in ipairs vlan_list
          return true, "vlan #{_val} matched" if v == _val
        false, "vlan #{_val} not in list"
      compile_nft: (family) ->
        -- Inline VLAN list: use explicit matching for small lists
        -- For larger lists, nft sets would be better
        vlan_str = table.concat([tostring(v) for v in *vlan_list], ", ")
        return "vlan id { #{vlan_str} }", nil
      creates_dynamic_scope: false
    }
