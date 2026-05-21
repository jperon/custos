local _schema = {
  label = "Ordinateur volé",
  description = "Bloque les requêtes depuis une liste noire de MACs",
  category = "source",
  arg_type = "string_list",
  arg_hint = "liste de MACs aa:bb:cc:dd:ee:ff"
}
local _factory
_factory = function(cfg)
  return function(macs)
    if not (type(macs) == "table") then
      return {
        capabilities = {
          worker = true,
          nft = false,
          nft_dynamic = false
        },
        eval = function(req)
          return false, "stolen_computer requires a table of MACs"
        end
      }
    end
    local blacklist = { }
    local macs_lower = { }
    for _index_0 = 1, #macs do
      local mac = macs[_index_0]
      local mac_lower = mac:lower()
      blacklist[mac_lower] = true
      macs_lower[#macs_lower + 1] = mac_lower
    end
    return {
      capabilities = {
        worker = true,
        nft = true,
        nft_dynamic = false
      },
      macs = macs,
      eval = function(req)
        local _mac = req.mac
        if not (_mac) then
          return false, "MAC not available"
        end
        if blacklist[_mac:lower()] then
          return true, "Stolen computer: " .. tostring(_mac)
        else
          return false, "MAC " .. tostring(_mac) .. " not in blacklist"
        end
      end,
      compile_nft = function(family)
        local mac_str = table.concat(macs_lower, ", ")
        return "ether saddr { " .. tostring(mac_str) .. " }", nil
      end
    }
  end
end
return {
  schema = _schema,
  factory = _factory
}
