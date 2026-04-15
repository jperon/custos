-- src/parse/ethernet.moon
-- Décodage L2 : extraction des adresses MAC depuis les métadonnées NFQUEUE.
--
-- En mode bridge (BRIDGE_MODE=1), nfq_get_payload() retourne la trame
-- Ethernet complète. La MAC source est extraite directement depuis le
-- payload (octets 6–11), ce qui est plus fiable que nfq_get_packet_hw()
-- qui peut être absent sur certains hooks bridge.
--
-- En mode routeur (BRIDGE_MODE=0), seul le paquet IP est livré par
-- NFQUEUE ; nfq_get_packet_hw() fournit la MAC source.

{ :ffi, :libnfq } = require "ffi_defs"
{ :BRIDGE_MODE } = require "config"
bit = require "bit"

ETH_OFFSET = BRIDGE_MODE and 14 or 0

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
-- En mode bridge : lit la MAC source depuis les octets 6–11 du payload Ethernet.
-- En mode routeur : utilise nfq_get_packet_hw() (seule la MAC source est exposée).
-- Les paquets OUTPUT locaux n'ont pas de hw_addr : mac_src vaut "unknown",
-- mac_raw vaut 6 octets nuls.
-- @tparam cdata nfad     Pointeur nfq_data* (paramètre du callback NFQUEUE).
-- @tparam string|nil raw Payload brut (requis en mode bridge, nil accepté sinon).
-- @treturn table {mac_src: string, mac_raw: string, in_ifindex: number, vlan: number|nil}
get_l2 = (nfad, raw) ->
  mac_src = "unknown"
  mac_raw = "\0\0\0\0\0\0"

  if BRIDGE_MODE and raw and #raw >= 12
    -- Mode bridge : MAC source aux octets 6–11 de la trame Ethernet.
    p = ffi.cast "const uint8_t*", raw
    mac_src = format_mac_ptr p, 6
    mac_raw = ffi.string p + 6, 6
  else
    -- Mode routeur : nfq_get_packet_hw() retourne la MAC source.
    hw = libnfq.nfq_get_packet_hw nfad
    if hw != nil and hw.hw_addrlen > 0
      mac_src = format_mac hw
      mac_raw = ffi.string hw.hw_addr, 6

  in_ifindex = tonumber libnfq.nfq_get_indev nfad
  mark = tonumber libnfq.nfq_get_nfmark nfad
  vlan = mark > 0 and mark or nil

  { :mac_src, :mac_raw, :in_ifindex, :vlan }

{ :get_l2, :format_mac, :format_mac_ptr, :ETH_OFFSET }
