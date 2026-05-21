local _schema = {
  label = "Adresse MAC source",
  description = "Requête depuis une adresse MAC spécifique (support nft natif)",
  category = "source",
  arg_type = "string",
  arg_hint = "ex: aa:bb:cc:dd:ee:ff"
}
local _factory
_factory = function(cfg)
  return function(mac_or_alias)
    local mac_map = cfg.macs or { }
    local target_mac = nil
    if mac_or_alias and mac_or_alias ~= "_any" and mac_or_alias ~= "_none" then
      target_mac = (mac_map[mac_or_alias] or mac_or_alias):lower()
    end
    if mac_or_alias == "_any" then
      return {
        capabilities = {
          worker = true,
          nft = false,
          nft_dynamic = false
        },
        mac_or_alias = mac_or_alias,
        eval = function(req)
          local _mac = req.mac
          return _mac ~= nil, "MAC available"
        end
      }
    end
    if mac_or_alias == "_none" then
      return {
        capabilities = {
          worker = true,
          nft = false,
          nft_dynamic = false
        },
        mac_or_alias = mac_or_alias,
        eval = function(req)
          local _mac = req.mac
          return _mac == nil, "MAC not available"
        end
      }
    end
    return {
      capabilities = {
        worker = true,
        nft = true,
        nft_dynamic = false
      },
      mac_or_alias = mac_or_alias,
      target_mac = target_mac,
      eval = function(req)
        local _mac = req.mac
        if not (_mac) then
          return false, "MAC not available"
        end
        return _mac:lower() == target_mac, "MAC " .. tostring(_mac) .. " vs " .. tostring(target_mac)
      end,
      compile_nft = function(family)
        return "ether saddr " .. tostring(target_mac), nil
      end
    }
  end
end
return {
  schema = _schema,
  factory = _factory
}
