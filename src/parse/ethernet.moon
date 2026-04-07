-- src/parse/ethernet.moon
-- Décodage L2 : extraction des adresses MAC depuis les métadonnées NFQUEUE.
--
-- Note sur les limites de l'API NFQUEUE :
--   nfq_get_packet_hw() retourne uniquement la MAC *source* du dernier
--   segment traversé (l'émetteur sur le segment LAN). La MAC destination
--   n'est pas exposée par cette API sur les hooks FORWARD/bridge — elle
--   serait disponible en parsant le payload Ethernet brut, ce qui nécessite
--   un hook de type NF_NETDEV ou un AF_PACKET raw socket hors de notre scope.

{ :ffi, :libnfq } = require "ffi_defs"

--- Formate 6 octets MAC en chaîne "aa:bb:cc:dd:ee:ff".
-- @tparam cdata hw_ptr Pointeur vers nfqnl_msg_packet_hw
-- @treturn string Adresse MAC formatée
format_mac = (hw_ptr) ->
  string.format "%02x:%02x:%02x:%02x:%02x:%02x",
    hw_ptr.hw_addr[0], hw_ptr.hw_addr[1], hw_ptr.hw_addr[2],
    hw_ptr.hw_addr[3], hw_ptr.hw_addr[4], hw_ptr.hw_addr[5]

--- Extrait les informations L2 depuis les métadonnées nfq_data.
-- Retourne une table avec la MAC source (texte + brute) et l'index d'interface.
-- Les paquets OUTPUT locaux n'ont pas de hw_addr : mac_src vaut "unknown",
-- mac_raw vaut 6 octets nuls.
-- @tparam cdata nfad Pointeur nfq_data* (paramètre du callback NFQUEUE)
-- @treturn table {mac_src: string, mac_raw: string, in_ifindex: number}
get_l2 = (nfad) ->
  hw = libnfq.nfq_get_packet_hw nfad
  mac_src = "unknown"
  mac_raw = "\0\0\0\0\0\0"
  if hw != nil and hw.hw_addrlen > 0
    mac_src = format_mac hw
    mac_raw = ffi.string hw.hw_addr, 6

  -- Index de l'interface d'entrée (non disponible pour OUTPUT)
  in_ifindex = tonumber libnfq.nfq_get_indev nfad

  { :mac_src, :mac_raw, :in_ifindex }

{ :get_l2, :format_mac }
