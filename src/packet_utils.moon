-- src/packet_utils.moon
-- Helpers partagés pour parser des paquets IP communs aux workers DNS.

{ :ffi } = require "ffi_defs"
{ new: new_stream } = require "ipparse.l4.tcp_stream"
{ :parse_ip4, :parse_ip6, :parse_udp, :parse_tcp, :parse_dns } = require "lib.packet_parsing"
{ :PROTO_UDP, :PROTO_TCP } = require "lib.checksums"
bit = require "bit"

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

--- Formate 6 octets d'une chaîne Lua en adresse MAC textuelle.
-- @tparam string s   Chaîne d'au moins off+5 octets
-- @tparam number off Offset 1-based du premier octet (défaut 1)
-- @treturn string Adresse MAC "aa:bb:cc:dd:ee:ff"
mac2s = (s, off=1) ->
  string.format "%02x:%02x:%02x:%02x:%02x:%02x",
    s\byte(off),   s\byte(off+1), s\byte(off+2),
    s\byte(off+3), s\byte(off+4), s\byte(off+5)

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

--- Parse un paquet IP jusqu'au message DNS (UDP ou DNS-TCP réassemblé).
-- Implémentation unique partagée par worker_questions et worker_responses.
-- L'état de réassemblage TCP reste propre à chaque worker : il est passé en
-- argument (un module = un processus après fork).
-- @tparam string raw Paquet IP brut
-- @tparam table tcp_state Réassembleur DNS-TCP du worker (cf. new_dns_tcp_stream)
-- @treturn table|nil ip En-tête IP parsé
-- @treturn table|string|nil l4 En-tête L4, ou statut "parse_failed",
--   "buffering" (segment TCP intermédiaire) ou "tcp_control" (SYN/FIN/RST sans
--   charge utile DNS)
-- @treturn table|nil dns_msg Message DNS parsé
-- @treturn string|nil dns_raw Payload DNS brut
-- @treturn number|nil ip_ihl Offset 0-based de L4 dans le paquet
parse_dns_packet = (raw, tcp_state) ->
  ver = bit.rshift raw\byte(1), 4
  ip = if ver == 4
    ip4, _ = parse_ip4 raw
    ip4
  elseif ver == 6
    ip6, _ = parse_ip6 raw
    ip6
  return nil, "parse_failed" unless ip

  l4_off = ip.data_off
  proto  = ip.protocol or ip.next_header
  ip_ihl = ip.payload_off or (ip.data_off - 1)   -- offset 0-based de L4

  if ip.version == 6
    p = ffi.cast "const uint8_t*", raw
    proto, l4_off_0based = skip_ipv6_ext_hdrs p, #raw, ip.next_header
    return nil, "parse_failed" unless proto
    l4_off = l4_off_0based + 1
    ip_ihl = l4_off_0based

  if proto == PROTO_UDP
    udp, _ = parse_udp raw, l4_off
    return nil, "parse_failed" unless udp
    dns_raw = raw\sub udp.data_off, udp.off + udp.len - 1
    dns_msg, _ = parse_dns dns_raw, 1, false
    return nil, "parse_failed" unless dns_msg
    udp.proto = "udp"
    return ip, udp, dns_msg, dns_raw, ip_ihl

  elseif proto == PROTO_TCP
    tcp, _ = parse_tcp raw, l4_off
    return nil, "parse_failed" unless tcp
    payload = raw\sub tcp.data_off
    is_fin_rst = bit.band(tcp.flags, 0x05) != 0
    has_payload = payload != ""
    -- Clé de reassembly : octets IP bruts (largeur fixe, byte-safe) plutôt que
    -- ip2s (évite deux inet_ntop + allocations par segment TCP). Clé opaque,
    -- jamais re-parsée.
    key = "#{ip.src}|#{tcp.spt}|#{ip.dst}|#{tcp.dpt}"
    buf, init_seq, first_seg = tcp_state.feed key, payload, tcp.flags, tcp.seq_n
    unless buf
      return nil, if is_fin_rst or not has_payload then "tcp_control" else "buffering"
    dns_raw = buf\sub 3
    dns_msg, _ = parse_dns dns_raw, 1, false
    return nil, "parse_failed" unless dns_msg
    tcp.proto = "tcp"
    tcp.tcp_init_seq = init_seq
    tcp.tcp_single_segment = first_seg
    tcp.tcp_dns_raw = dns_raw
    return ip, tcp, dns_msg, dns_raw, ip_ihl

  nil, "parse_failed"

{ :skip_ipv6_ext_hdrs, :mac2s, :dns_tcp_complete, :new_dns_tcp_stream, :parse_dns_packet }
