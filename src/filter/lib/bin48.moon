-- src/filter/lib/bin48.moon
-- Variante 48 bits du stockage des listes de domaines.
--
-- Au lieu de N × 8 octets (uint64_t), on stocke N × 6 octets : le hash xxh64
-- tronqué à ses 48 bits de poids faible, en little-endian, trié croissant.
-- Gain : −25 % de stockage et de RAM. Faux positif d'un lookup ≈ N / 2⁴⁸,
-- soit ~5·10⁻⁸ pour N = 5·10⁶ — négligeable, du même ordre que les collisions
-- internes déjà tolérées en uint64.
--
-- Contrainte : il n'existe pas de type natif uint48. Les enregistrements de
-- 6 octets ne sont pas alignés sur 8 ; on ne peut donc PAS faire un simple
-- `ffi.cast "uint64_t*"`. On lit chaque enregistrement octet par octet, ce qui
-- reste portable sur les cibles MIPS/ARM d'OpenWrt (pas d'accès non aligné).

ffi = require "ffi"

-- 2⁴⁸ : diviseur pour tronquer / reconstruire sur 48 bits.
TWO48 = 0x1000000000000ULL

--- Tronque un hash uint64 à ses 48 bits de poids faible.
-- @tparam cdata h uint64_t
-- @treturn cdata uint64_t dans [0, 2⁴⁸)
truncate = (h) -> h % TWO48

--- Empaquette un tableau de hashes (déjà tronqués 48 bits, triés croissant)
-- en une chaîne de N × 6 octets little-endian.
-- @tparam table  hashes Tableau 1-indexé de cdata uint64_t (valeurs < 2⁴⁸)
-- @tparam number n      Nombre d'entrées
-- @treturn string       Chaîne de n*6 octets
pack = (hashes, n) ->
  buf = ffi.new "uint8_t[?]", n * 6
  for i = 1, n
    v = hashes[i]
    base = (i - 1) * 6
    for k = 0, 5
      buf[base + k] = tonumber v % 256ULL
      v = v / 256ULL
  ffi.string buf, n * 6

-- Lecture octet par octet : portable partout, mais lente (boucle cdata non
-- jittée). Repli pour les architectures n'autorisant pas l'accès non aligné.
rec_at_bytewise = (arr8, i) ->
  b = arr8 + i * 6
  v = 0ULL
  for k = 5, 0, -1
    v = v * 256ULL + b[k]
  v

-- Lecture non alignée 32 + 16 bits : ~60× plus rapide, mais nécessite que
-- l'architecture tolère les accès mémoire non alignés.
TWO32 = 0x100000000ULL
_u32 = ffi.typeof "const uint32_t*"
_u16 = ffi.typeof "const uint16_t*"
rec_at_unaligned = (arr8, i) ->
  b = arr8 + i * 6
  ffi.cast("uint64_t", (ffi.cast _u32, b)[0]) +
    ffi.cast("uint64_t", (ffi.cast _u16, b + 4)[0]) * TWO32

-- Sélection à l'import selon l'architecture LuaJIT. x86/x64/ARM(v7+)/ARM64
-- tolèrent l'accès non aligné (ARM le trappe-et-émule au pire) ; MIPS le
-- trappe et l'émulation noyau est très coûteuse → octet par octet.
_arch = (require "jit").arch
_unaligned_ok = { x86: true, x64: true, arm: true, arm64: true, ppc: true }

--- Lit l'enregistrement i (0-indexé) depuis un pointeur uint8_t* sur 6 octets.
-- @tparam cdata  arr8 const uint8_t*
-- @tparam number i    Index 0-indexé
-- @treturn cdata uint64_t reconstruit (48 bits utiles)
rec_at = _unaligned_ok[_arch] and rec_at_unaligned or rec_at_bytewise

--- Hache, tronque, déduplique et empaquette une liste de domaines.
-- Centralise le format .bin (48 bits) pour tous les producteurs (updater,
-- convert, classifier). Déduplication par chaîne de domaine.
-- @tparam table domains Tableau de chaînes
-- @treturn string payload (n*6 octets), ou "" si aucun domaine
-- @treturn number n nombre d'entrées uniques
pack_domains = (domains) ->
  xxhash = require "ffi_xxhash"
  seen, h, n = {}, {}, 0
  for d in *domains
    continue if seen[d]
    seen[d] = true
    n += 1
    h[n] = truncate xxhash.xxh64 d
  return "", 0 if n == 0
  table.sort h, (a, b) -> a < b
  (pack h, n), n

--- Recherche binaire dans un buffer de N enregistrements 6 octets triés.
-- @tparam cdata  arr8   const uint8_t* (n*6 octets)
-- @tparam number n      Nombre d'enregistrements
-- @tparam cdata  target uint64_t déjà tronqué 48 bits (cf. truncate)
-- @treturn boolean true si présent
bsearch = (arr8, n, target) ->
  lo, hi = 0, n - 1
  while lo <= hi
    mid = math.floor (lo + hi) * 0.5
    v = rec_at arr8, mid
    if v == target
      return true
    elseif v < target
      lo = mid + 1
    else
      hi = mid - 1
  false

{ :truncate, :pack, :pack_domains, :rec_at, :rec_at_bytewise, :rec_at_unaligned, :bsearch, :TWO48 }
