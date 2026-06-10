-- src/packet_utils.moon
-- Helpers partagés pour parser des paquets IP communs aux workers DNS.

{ new: new_stream } = require "ipparse.l4.tcp_stream"

IPV6_EXT_HDRS = {
  [0]:   true   -- Hop-by-Hop Options
  [43]:  true   -- Routing
  [44]:  true   -- Fragment
  [51]:  false  -- Authentication Header (AH)
  [60]:  true   -- Destination Options
  [135]: true   -- Mobility
  [139]: true   -- HIP
  [140]: true   -- Shim6
}

--- Saute les en-têtes d'extension IPv6 et renvoie le prochain protocole L4.
-- @tparam cdata p    Paquet IP brut casté en uint8_t*
-- @tparam number len Longueur du paquet
-- @tparam number first_nh Prochain header initial (ip.next_header)
-- @treturn number|nil Prochain protocole L4
-- @treturn number|nil Offset 0-based du L4, ou nil en cas d'extension invalide
skip_ipv6_ext_hdrs = (p, len, first_nh) ->
  nh  = first_nh
  off = 40
  while IPV6_EXT_HDRS[nh] != nil
    return nil, nil if off + 2 > len
    next_nh  = p[off]
    ext_size = if nh == 51
      (p[off + 1] + 2) * 4   -- AH
    else
      (p[off + 1] + 1) * 8   -- standard
    return nil, nil if ext_size < 8 or off + ext_size > len
    off += ext_size
    nh   = next_nh
  nh, off

--- Renvoie true si le buffer contient un message DNS TCP complet.
-- Le préfixe DNS-over-TCP est 2 octets de longueur, puis le payload DNS.
-- @tparam string buf Buffer accumulé par le réassembleur TCP
-- @treturn boolean
dns_tcp_complete = (buf) ->
  return false if #buf < 2
  #buf >= 2 + buf\byte(1) * 256 + buf\byte(2)

--- Construit un réassembleur TCP spécialisé pour DNS.
-- @tparam function check_complete Prédicat de complétude
-- @treturn table Réassembleur tcp_stream
new_dns_tcp_stream = (check_complete=dns_tcp_complete) ->
  new_stream check_complete

{ :skip_ipv6_ext_hdrs, :dns_tcp_complete, :new_dns_tcp_stream }
