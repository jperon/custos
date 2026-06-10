-- tests/unit/lib/checksums_spec.moon
ffi = require "ffi"
bit = require "bit"
C   = require "lib.checksums"

-- Somme de contrôle de référence (RFC 1071) sur un buffer FFI : doit valoir
-- 0xFFFF quand le checksum déjà posé est inclus dans la sommation.
fold_ones = (buf, len) ->
  sum = 0
  i = 0
  while i + 1 < len
    sum += bit.bor bit.lshift(buf[i], 8), buf[i + 1]
    i += 2
  sum += bit.lshift buf[i], 8 if i < len
  while bit.rshift(sum, 16) != 0
    sum = bit.band(sum, 0xFFFF) + bit.rshift(sum, 16)
  sum

describe "lib.checksums", ->
  describe "accès byte-level big-endian", ->
    it "w16 puis r16 font un aller-retour", ->
      p = ffi.new "uint8_t[4]", 0
      C.w16 p, 0, 0xBEEF
      assert.equals 0xBE, p[0]
      assert.equals 0xEF, p[1]
      assert.equals 0xBEEF, C.r16 p, 0

    it "w32 écrit en big-endian", ->
      p = ffi.new "uint8_t[4]", 0
      C.w32 p, 0, 0x01020304
      assert.equals 0x01, p[0]
      assert.equals 0x02, p[1]
      assert.equals 0x03, p[2]
      assert.equals 0x04, p[3]

  describe "fold16", ->
    it "replie une somme avec retenue", ->
      assert.equals 0x0001, C.fold16 0x10000
      assert.equals 0xFFFF, C.fold16 0xFFFF

  describe "fix_ip4_cksum", ->
    it "produit un en-tête IPv4 dont la somme de contrôle est valide", ->
      -- En-tête IPv4 minimal (20 octets), champs arbitraires mais cohérents.
      buf = ffi.new "uint8_t[20]", 0
      buf[0] = 0x45                 -- version 4, IHL 5
      C.w16 buf, 2, 20              -- total length
      buf[8] = 64                   -- TTL
      buf[9] = C.PROTO_UDP
      buf[12], buf[13], buf[14], buf[15] = 192, 168, 0, 1
      buf[16], buf[17], buf[18], buf[19] = 192, 168, 0, 2
      C.fix_ip4_cksum buf, 20
      assert.equals 0xFFFF, fold_ones buf, 20

  describe "fix_l4_cksum", ->
    it "calcule un checksum UDP/IPv4 valide", ->
      -- IPv4 (20) + UDP (8) + 4 octets de données.
      pkt_len = 32
      buf = ffi.new "uint8_t[?]", pkt_len, 0
      buf[0] = 0x45
      C.w16 buf, 2, pkt_len
      buf[9] = C.PROTO_UDP
      buf[12], buf[13], buf[14], buf[15] = 10, 0, 0, 1
      buf[16], buf[17], buf[18], buf[19] = 10, 0, 0, 2
      C.w16 buf, 20, 4444           -- src port
      C.w16 buf, 22, 53             -- dst port
      C.w16 buf, 24, 12             -- UDP length (8 + 4)
      buf[28], buf[29], buf[30], buf[31] = 0xDE, 0xAD, 0xBE, 0xEF
      C.fix_l4_cksum buf, pkt_len, 20, 4, C.PROTO_UDP
      -- Vérifie via le pseudo-header : somme(pseudo + segment UDP) == 0xFFFF.
      sum = 0
      for i = 12, 18, 2
        sum += C.r16 buf, i
      sum += C.PROTO_UDP + 12
      i = 20
      while i < pkt_len
        sum += C.r16 buf, i
        i += 2
      assert.equals 0xFFFF, C.fold16 sum

    it "ne touche pas un paquet trop court", ->
      buf = ffi.new "uint8_t[24]", 0   -- IPv4(20) + seulement 4 octets L4
      before = buf[20]
      C.fix_l4_cksum buf, 24, 20, 4, C.PROTO_UDP
      assert.equals before, buf[20]
