-- src/parse/ethernet.moon
-- Décodage L2 : extraction des adresses MAC depuis les métadonnées NFQUEUE.
--
-- Dans la table bridge nftables, nfq_get_payload() retourne le paquet
-- à partir de l'en-tête IP (aucun en-tête Ethernet dans le payload).
-- La MAC source est donc lue via nfq_get_packet_hw() ; la MAC destination
-- n'est pas exposée par libnetfilter_queue et reste "unknown" (les workers
-- qui en ont besoin utilisent neigh.get_mac(ip) en fallback).

{ :ffi, :libnfq } = require "ffi_defs"

--- Formate 6 octets d'un pointeur FFI en chaîne "aa:bb:cc:dd:ee:ff".
-- @tparam cdata p   uint8_t pointer.
-- @tparam number o  0-based byte offset.
-- @treturn string Adresse MAC formatée.
format_mac_ptr = (p, o) ->
  string.format "%02x:%02x:%02x:%02x:%02x:%02x",
    p[o], p[o+1], p[o+2], p[o+3], p[o+4], p[o+5]

--- Formate 6 octets d'un nfqnl_msg_packet_hw en chaîne "aa:bb:cc:dd:ee:ff".
-- @tparam cdata hw_ptr Pointeur vers nfqnl_msg_packet_hw.
-- @treturn string Adresse MAC formatée.
format_mac = (hw_ptr) ->
  string.format "%02x:%02x:%02x:%02x:%02x:%02x",
    hw_ptr.hw_addr[0], hw_ptr.hw_addr[1], hw_ptr.hw_addr[2],
    hw_ptr.hw_addr[3], hw_ptr.hw_addr[4], hw_ptr.hw_addr[5]

--- Extrait les informations L2 depuis les métadonnées nfq_data.
-- Utilise nfq_get_packet_hw() pour obtenir la MAC source (la seule exposée
-- par libnetfilter_queue). Les paquets OUTPUT locaux n'ont pas de hw_addr :
-- mac_src vaut "unknown" et mac_raw vaut 6 octets nuls.
-- @tparam cdata nfad Pointeur nfq_data* (paramètre du callback NFQUEUE).
-- @treturn table {mac_src: string, mac_dst: string, mac_raw: string, in_ifindex: number, vlan: number|nil}
get_l2 = (nfad) ->
  mac_src = "unknown"
  mac_dst = "unknown"
  mac_raw = "\0\0\0\0\0\0"

  hw = libnfq.nfq_get_packet_hw nfad
  if hw != nil and hw.hw_addrlen > 0
    mac_src = format_mac hw
    mac_raw = ffi.string hw.hw_addr, 6

  in_ifindex = tonumber libnfq.nfq_get_indev nfad
  mark = tonumber libnfq.nfq_get_nfmark nfad
  vlan = mark > 0 and mark or nil

  { :mac_src, :mac_dst, :mac_raw, :in_ifindex, :vlan }

{ :get_l2, :format_mac, :format_mac_ptr }
