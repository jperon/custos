-- Codec partagé pour la table de cibles de strip CNAME (mac_learner).
-- name_hash : FNV-1a 64 bits sur le nom normalisé, sérialisé en 8 octets BE.
-- Le hash (au lieu du nom variable) garde des messages pipe à taille fixe.

ffi = require "ffi"
bit = require "bit"

STRIP_MSG_SIZE = 10   -- 8 octets hash + 2 octets rr_code (uint16 BE)

FNV_OFFSET = 0xcbf29ce484222325ULL
FNV_PRIME  = 0x100000001b3ULL

normalize = (name) ->
  return "" unless name and name != ""
  (tostring name)\lower!\gsub "%.+$", ""

-- xor d'un octet dans un uint64 sans dépendre de `bit` (qui est 32 bits) :
-- on xor uniquement l'octet de poids faible via bit.bxor (32 bits suffisent
-- pour cet octet), puis on recompose le uint64_t.
bit_xor_byte = (h, b) ->
  lo = tonumber(h % 256ULL)
  xored = bit.bxor lo, b
  (h - lo) + xored

--- FNV-1a 64 bits → 8 octets big-endian.
name_hash = (name) ->
  h = FNV_OFFSET
  s = normalize name
  for i = 1, #s
    h = bit_xor_byte h, s\byte(i)
    h = h * FNV_PRIME
  out = {}
  for shift = 56, 0, -8
    out[#out + 1] = string.char tonumber((h / (2ULL ^ shift)) % 256ULL)
  table.concat out

encode = (name, rr_code) ->
  rr = tonumber(rr_code) or 0
  name_hash(name) .. string.char(math.floor(rr / 256) % 256, rr % 256)

decode = (msg) ->
  return nil unless msg and #msg >= STRIP_MSG_SIZE
  hash8 = msg\sub 1, 8
  rr = msg\byte(9) * 256 + msg\byte(10)
  hash8, rr

{ :normalize, :name_hash, :encode, :decode, :STRIP_MSG_SIZE }
