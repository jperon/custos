-- src/filter/conditions/_match_mac.moon
-- Condition abstraite : vérifie si l'adresse MAC source correspond.
-- Dans custos, req.mac est toujours rempli depuis le header NFQUEUE
-- (nfq_get_packet_hw) → pas besoin de résolution IP→MAC.
-- Adapté de shelterfilter conditions/_match_mac.moon : suppression de popen.

--- @tparam string prop Nom de la propriété MAC dans req (ex. "mac")
-- @treturn function factory (cfg) → (mac) → (req) → bool
(prop) ->
  (cfg) -> (mac) ->
    mac = mac\lower!

    --- @tparam table req {mac: string, src_ip: string, ...}
    -- @treturn boolean, string
    (req) ->
      _mac = req[prop]
      return false, "MAC not available in request" unless _mac
      _mac\lower! == mac, "MAC #{_mac} vs #{mac}"
