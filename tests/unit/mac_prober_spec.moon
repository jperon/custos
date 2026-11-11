-- tests/unit/mac_prober_spec.moon
-- T2 : helpers purs de mac_prober (trames ARP / Neighbor Solicitation et
-- parseurs de réponses). Aucun socket : construction de trames et vérification
-- indépendante des checksums (RFC 1071 / RFC 4443).

ffi = require "ffi"
bit = require "bit"
sp  = require("ipparse.lib.pack_compat").pack

-- lib.socket déclare htons/inet_pton (nécessaires au chargement de mac_prober).
pcall require, "lib.socket"
mp = require "mac_prober"

OUR_MAC  = "\170\187\204\221\238\255"                       -- aa:bb:cc:dd:ee:ff
RESP_MAC = "\2\0\0\0\0\1"                                   -- 02:00:00:00:00:01
OUR_IP6  = "\254\128" .. string.rep("\0", 13) .. "\1"        -- fe80::1
TGT_IP4  = "\192\0\2\10"                                    -- 192.0.2.10
TGT_IP6  = "\32\1\13\184" .. string.rep("\0", 10) .. "\202\254" -- 2001:db8::cafe

-- Somme de complément à 1, indépendante des helpers de production.
ones_sum = (s) ->
  sum = 0
  i = 1
  while i + 1 <= #s
    sum += s\byte(i) * 256 + s\byte(i + 1)
    i += 2
  sum += s\byte(i) * 256 if i == #s
  sum

fold16 = (sum) ->
  while bit.rshift(sum, 16) != 0
    sum = bit.band(sum, 0xFFFF) + bit.rshift(sum, 16)
  sum

-- Vrai si la somme de toutes les parties (checksum inclus) vaut 0xFFFF.
cksum_valid = (parts) ->
  total = 0
  for p in *parts
    total += ones_sum p
  fold16(total) == 0xFFFF

pseudo6 = (src6, dst6, payload) ->
  src6 .. dst6 .. sp(">I4", #payload) .. "\0\0\0" .. string.char(58)

-- Trame Ethernet + ARP de 42 octets.
build_arp_frame = (op, sha, spa) ->
  "\255\255\255\255\255\255" .. RESP_MAC .. "\8\6" ..
    "\0\1\8\0\6\4" .. sp(">H", op) .. sha .. spa .. OUR_MAC .. TGT_IP4

-- Trame Ethernet + IPv6 + ICMPv6 NA (type 136), avec option TLLA optionnelle.
build_na_frame = (opts={}) ->
  na_type  = opts.na_type or 136
  next_hdr = opts.next_hdr or 58
  target   = opts.target or TGT_IP6
  src_mac  = opts.src_mac or RESP_MAC
  src6     = opts.src6 or OUR_IP6
  with_opt = if opts.with_opt == nil then true else opts.with_opt
  body = string.char(na_type, 0, 0, 0) .. "\0\0\0\0" .. target
  body ..= string.char(1, 1) .. src_mac if with_opt
  hdr = string.char(0x60, 0, 0, 0) .. sp(">H", #body) ..
    string.char(next_hdr, 64) .. src6 .. OUR_IP6
  OUR_MAC .. src_mac .. "\134\221" .. hdr .. body

describe "mac_prober", ->

  describe "build_arp_request", ->
    it "produit exactement la trame ARP probe attendue (42 octets)", ->
      frame = mp.build_arp_request OUR_MAC, TGT_IP4
      expected = "\255\255\255\255\255\255" .. OUR_MAC .. "\8\6" ..
        "\0\1\8\0\6\4\0\1" .. OUR_MAC ..
        "\0\0\0\0" .. "\0\0\0\0\0\0" .. TGT_IP4
      assert.equals 42, #frame
      assert.equals expected, frame

  describe "icmpv6_cksum", ->
    payload = "\135\0\0\0" .. "\0\0\0\0" .. TGT_IP6 .. "\1\1" .. OUR_MAC

    it "produit un checksum dont la vérification RFC 4443 vaut 0xFFFF", ->
      ck = mp.icmpv6_cksum OUR_IP6, TGT_IP6, payload
      assert.is_true ck > 0
      signed = payload\sub(1, 2) ..
        string.char(bit.rshift(ck, 8), bit.band(ck, 0xFF)) .. payload\sub(5)
      assert.is_true cksum_valid { pseudo6(OUR_IP6, TGT_IP6, payload), signed }

    it "change quand un octet du payload change", ->
      a = mp.icmpv6_cksum OUR_IP6, TGT_IP6, payload
      b = mp.icmpv6_cksum OUR_IP6, TGT_IP6, payload\sub(1, 15) ..
        string.char(payload\byte(16) + 1) .. payload\sub(17)
      assert.not_equals a, b

  describe "build_ns_frame", ->
    sol = "\255\2" .. string.rep("\0", 9) .. "\1\255" .. TGT_IP6\sub(14, 16)
    frame = mp.build_ns_frame OUR_MAC, OUR_IP6, TGT_IP6

    it "construit une trame de 86 octets avec les bons en-têtes", ->
      assert.equals 86, #frame
      -- Ethernet : multicast solicited-node, MAC source, EtherType IPv6.
      assert.equals "\51\51\255" .. TGT_IP6\sub(14, 16), frame\sub(1, 6)
      assert.equals OUR_MAC, frame\sub(7, 12)
      assert.equals "\134\221", frame\sub(13, 14)
      -- IPv6 : version 6, payload 32, next_header 58, hop limit 255.
      assert.equals 0x60, frame\byte(15)
      assert.equals 32, frame\byte(19) * 256 + frame\byte(20)
      assert.equals 58, frame\byte(21)
      assert.equals 255, frame\byte(22)
      assert.equals OUR_IP6, frame\sub(23, 38)
      assert.equals sol, frame\sub(39, 54)

    it "ICMPv6 : type NS, cible et option SLLA", ->
      assert.equals 135, frame\byte(55)
      assert.equals 0, frame\byte(56)
      assert.equals TGT_IP6, frame\sub(63, 78)
      assert.equals "\1\1", frame\sub(79, 80)
      assert.equals OUR_MAC, frame\sub(81, 86)

    it "checksum ICMPv6 valide sur le pseudo-header", ->
      payload = frame\sub(55, 86)
      assert.is_true cksum_valid { pseudo6(OUR_IP6, sol, payload), payload }

  describe "parse_arp_reply", ->
    it "accepte une reply dont le SPA est la cible sondée", ->
      frame = build_arp_frame 2, RESP_MAC, TGT_IP4
      ip, mac = mp.parse_arp_reply frame, #frame, TGT_IP4
      assert.equals "192.0.2.10", ip
      assert.equals "02:00:00:00:00:01", mac

    it "rejette une reply dont le SPA diffère de la cible", ->
      frame = build_arp_frame 2, RESP_MAC, "\192\0\2\99"
      ip, mac = mp.parse_arp_reply frame, #frame, TGT_IP4
      assert.is_nil ip
      assert.is_nil mac

    it "rejette une ARP request (op=1)", ->
      frame = build_arp_frame 1, RESP_MAC, TGT_IP4
      ip, mac = mp.parse_arp_reply frame, #frame, TGT_IP4
      assert.is_nil ip
      assert.is_nil mac

    it "rejette une trame trop courte", ->
      frame = build_arp_frame 2, RESP_MAC, TGT_IP4
      ip, mac = mp.parse_arp_reply frame, 41, TGT_IP4
      assert.is_nil ip
      assert.is_nil mac

    it "rejette un type matériel ou une longueur d'adresse incorrecte", ->
      frame = build_arp_frame 2, RESP_MAC, TGT_IP4
      bad_hw = frame\sub(1, 14) .. "\0\2" .. frame\sub(17)
      ip, mac = mp.parse_arp_reply bad_hw, #bad_hw, TGT_IP4
      assert.is_nil ip
      bad_hlen = frame\sub(1, 18) .. "\5" .. frame\sub(20)
      ip, mac = mp.parse_arp_reply bad_hlen, #bad_hlen, TGT_IP4
      assert.is_nil ip

  describe "parse_na_reply", ->
    it "accepte un NA dont la cible est l'adresse sondée", ->
      frame = build_na_frame!
      ip, mac = mp.parse_na_reply frame, #frame, TGT_IP6
      assert.equals "fe80::1", ip
      assert.equals "02:00:00:00:00:01", mac

    it "rejette une cible différente", ->
      frame = build_na_frame target: "\32\1\13\184" .. string.rep("\0", 11) .. "\1"
      ip, mac = mp.parse_na_reply frame, #frame, TGT_IP6
      assert.is_nil ip
      assert.is_nil mac

    it "rejette un next_header non ICMPv6", ->
      frame = build_na_frame next_hdr: 17
      ip, mac = mp.parse_na_reply frame, #frame, TGT_IP6
      assert.is_nil ip
      assert.is_nil mac

    it "rejette un type ICMPv6 autre que NA", ->
      frame = build_na_frame na_type: 135
      ip, mac = mp.parse_na_reply frame, #frame, TGT_IP6
      assert.is_nil ip
      assert.is_nil mac

    it "rejette une trame sans option TLLA (trop courte)", ->
      frame = build_na_frame with_opt: false
      assert.equals 78, #frame
      ip, mac = mp.parse_na_reply frame, #frame, TGT_IP6
      assert.is_nil ip
      assert.is_nil mac

  describe "parse_arp_frame", ->
    it "accepte toute reply valide et ignore une MAC nulle", ->
      frame = build_arp_frame 2, RESP_MAC, TGT_IP4
      ip, mac = mp.parse_arp_frame frame, #frame
      assert.equals "192.0.2.10", ip
      assert.equals "02:00:00:00:00:01", mac

      zero_mac = build_arp_frame 2, string.rep("\0", 6), TGT_IP4
      ip, mac = mp.parse_arp_frame zero_mac, #zero_mac
      assert.is_nil ip
      assert.is_nil mac

  describe "parse_na_frame", ->
    it "accepte un NA valide (sans option) et ignore une MAC source nulle", ->
      frame = build_na_frame with_opt: false
      ip, mac = mp.parse_na_frame frame, #frame
      assert.equals "2001:db8::cafe", ip
      assert.equals "02:00:00:00:00:01", mac

      zero_src = build_na_frame with_opt: false, src_mac: string.rep("\0", 6)
      ip, mac = mp.parse_na_frame zero_src, #zero_src
      assert.is_nil ip
      assert.is_nil mac

    it "rejette une trame trop courte", ->
      frame = build_na_frame with_opt: false
      ip, mac = mp.parse_na_frame frame, 77
      assert.is_nil ip
      assert.is_nil mac

  describe "conversions d'adresses", ->
    it "ip4_to_bin accepte une IPv4 valide et rejette le reste", ->
      assert.equals TGT_IP4, mp.ip4_to_bin "192.0.2.10"
      assert.is_nil mp.ip4_to_bin "pas.une.ip"
      assert.is_nil mp.ip4_to_bin "1.2.3"

    it "ip6_to_bin accepte une IPv6 valide et rejette le reste", ->
      assert.equals TGT_IP6, mp.ip6_to_bin "2001:db8::cafe"
      assert.is_nil mp.ip6_to_bin "pas::une::ip"
