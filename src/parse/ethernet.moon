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

-- Formate 6 octets MAC en chaîne "aa:bb:cc:dd:ee:ff"
format_mac = (hw_ptr) ->
  string.format "%02x:%02x:%02x:%02x:%02x:%02x",
    hw_ptr.hw_addr[0], hw_ptr.hw_addr[1], hw_ptr.hw_addr[2],
    hw_ptr.hw_addr[3], hw_ptr.hw_addr[4], hw_ptr.hw_addr[5]

-- Extrait les informations L2 depuis les métadonnées nfq_data.
-- Retourne une table { mac_src, in_ifindex } ou nil si non disponible
-- (les paquets OUTPUT locaux n'ont pas de hw_addr).
get_l2 = (nfad) ->
  hw = libnfq.nfq_get_packet_hw nfad
  mac_src = if hw != nil and hw.hw_addrlen > 0
    format_mac hw
  else
    "unknown"

  -- Index de l'interface d'entrée (non disponible pour OUTPUT)
  in_ifindex = tonumber libnfq.nfq_get_indev nfad

  { :mac_src, :in_ifindex }

{ :get_l2, :format_mac }
