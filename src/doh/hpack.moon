-- src/doh/hpack.moon
-- HPACK (RFC 7541) : décodeur complet et encodeur minimal.
--
-- Décodeur : entiers à préfixe (§5.1), chaînes littérales avec/sans Huffman
-- (§5.2, table de l'annexe B), table statique (annexe A), table dynamique par
-- connexion avec éviction et « dynamic table size update » (§6.3), champs
-- indexés et littéraux (avec/sans indexation, jamais indexés).
--
-- Toutes les bornes sont strictes : les erreurs sont retournées sous la forme
-- `nil, "raison"` ; aucune exception non capturée, aucune boucle sans borne.
--
-- Encodeur minimal : littéraux sans indexation et sans Huffman, plus les
-- champs indexés de la table statique (suffisant pour émettre une requête ou
-- une réponse HTTP/2).

bit = require "bit"

-- Table statique HPACK (RFC 7541 annexe A).
STATIC_TABLE = {
  { ":authority", "" }
  { ":method", "GET" }
  { ":method", "POST" }
  { ":path", "/" }
  { ":path", "/index.html" }
  { ":scheme", "http" }
  { ":scheme", "https" }
  { ":status", "200" }
  { ":status", "204" }
  { ":status", "206" }
  { ":status", "304" }
  { ":status", "400" }
  { ":status", "404" }
  { ":status", "500" }
  { "accept-charset", "" }
  { "accept-encoding", "gzip, deflate" }
  { "accept-language", "" }
  { "accept-ranges", "" }
  { "accept", "" }
  { "access-control-allow-origin", "" }
  { "age", "" }
  { "allow", "" }
  { "authorization", "" }
  { "cache-control", "" }
  { "content-disposition", "" }
  { "content-encoding", "" }
  { "content-language", "" }
  { "content-length", "" }
  { "content-location", "" }
  { "content-range", "" }
  { "content-type", "" }
  { "cookie", "" }
  { "date", "" }
  { "etag", "" }
  { "expect", "" }
  { "expires", "" }
  { "from", "" }
  { "host", "" }
  { "if-match", "" }
  { "if-modified-since", "" }
  { "if-none-match", "" }
  { "if-range", "" }
  { "if-unmodified-since", "" }
  { "last-modified", "" }
  { "link", "" }
  { "location", "" }
  { "max-forwards", "" }
  { "proxy-authenticate", "" }
  { "proxy-authorization", "" }
  { "range", "" }
  { "referer", "" }
  { "refresh", "" }
  { "retry-after", "" }
  { "server", "" }
  { "set-cookie", "" }
  { "strict-transport-security", "" }
  { "transfer-encoding", "" }
  { "user-agent", "" }
  { "vary", "" }
  { "via", "" }
  { "www-authenticate", "" }
}

-- Codes de Huffman (RFC 7541 annexe B) : {code, longueur en bits}, indexé par
-- symbole + 1 (0..255, puis EOS = 256).
HUFFMAN_TABLE = {
  {0x1ff8, 13}
  {0x7fffd8, 23}
  {0xfffffe2, 28}
  {0xfffffe3, 28}
  {0xfffffe4, 28}
  {0xfffffe5, 28}
  {0xfffffe6, 28}
  {0xfffffe7, 28}
  {0xfffffe8, 28}
  {0xffffea, 24}
  {0x3ffffffc, 30}
  {0xfffffe9, 28}
  {0xfffffea, 28}
  {0x3ffffffd, 30}
  {0xfffffeb, 28}
  {0xfffffec, 28}
  {0xfffffed, 28}
  {0xfffffee, 28}
  {0xfffffef, 28}
  {0xffffff0, 28}
  {0xffffff1, 28}
  {0xffffff2, 28}
  {0x3ffffffe, 30}
  {0xffffff3, 28}
  {0xffffff4, 28}
  {0xffffff5, 28}
  {0xffffff6, 28}
  {0xffffff7, 28}
  {0xffffff8, 28}
  {0xffffff9, 28}
  {0xffffffa, 28}
  {0xffffffb, 28}
  {0x14, 6}
  {0x3f8, 10}
  {0x3f9, 10}
  {0xffa, 12}
  {0x1ff9, 13}
  {0x15, 6}
  {0xf8, 8}
  {0x7fa, 11}
  {0x3fa, 10}
  {0x3fb, 10}
  {0xf9, 8}
  {0x7fb, 11}
  {0xfa, 8}
  {0x16, 6}
  {0x17, 6}
  {0x18, 6}
  {0x0, 5}
  {0x1, 5}
  {0x2, 5}
  {0x19, 6}
  {0x1a, 6}
  {0x1b, 6}
  {0x1c, 6}
  {0x1d, 6}
  {0x1e, 6}
  {0x1f, 6}
  {0x5c, 7}
  {0xfb, 8}
  {0x7ffc, 15}
  {0x20, 6}
  {0xffb, 12}
  {0x3fc, 10}
  {0x1ffa, 13}
  {0x21, 6}
  {0x5d, 7}
  {0x5e, 7}
  {0x5f, 7}
  {0x60, 7}
  {0x61, 7}
  {0x62, 7}
  {0x63, 7}
  {0x64, 7}
  {0x65, 7}
  {0x66, 7}
  {0x67, 7}
  {0x68, 7}
  {0x69, 7}
  {0x6a, 7}
  {0x6b, 7}
  {0x6c, 7}
  {0x6d, 7}
  {0x6e, 7}
  {0x6f, 7}
  {0x70, 7}
  {0x71, 7}
  {0x72, 7}
  {0xfc, 8}
  {0x73, 7}
  {0xfd, 8}
  {0x1ffb, 13}
  {0x7fff0, 19}
  {0x1ffc, 13}
  {0x3ffc, 14}
  {0x22, 6}
  {0x7ffd, 15}
  {0x3, 5}
  {0x23, 6}
  {0x4, 5}
  {0x24, 6}
  {0x5, 5}
  {0x25, 6}
  {0x26, 6}
  {0x27, 6}
  {0x6, 5}
  {0x74, 7}
  {0x75, 7}
  {0x28, 6}
  {0x29, 6}
  {0x2a, 6}
  {0x7, 5}
  {0x2b, 6}
  {0x76, 7}
  {0x2c, 6}
  {0x8, 5}
  {0x9, 5}
  {0x2d, 6}
  {0x77, 7}
  {0x78, 7}
  {0x79, 7}
  {0x7a, 7}
  {0x7b, 7}
  {0x7ffe, 15}
  {0x7fc, 11}
  {0x3ffd, 14}
  {0x1ffd, 13}
  {0xffffffc, 28}
  {0xfffe6, 20}
  {0x3fffd2, 22}
  {0xfffe7, 20}
  {0xfffe8, 20}
  {0x3fffd3, 22}
  {0x3fffd4, 22}
  {0x3fffd5, 22}
  {0x7fffd9, 23}
  {0x3fffd6, 22}
  {0x7fffda, 23}
  {0x7fffdb, 23}
  {0x7fffdc, 23}
  {0x7fffdd, 23}
  {0x7fffde, 23}
  {0xffffeb, 24}
  {0x7fffdf, 23}
  {0xffffec, 24}
  {0xffffed, 24}
  {0x3fffd7, 22}
  {0x7fffe0, 23}
  {0xffffee, 24}
  {0x7fffe1, 23}
  {0x7fffe2, 23}
  {0x7fffe3, 23}
  {0x7fffe4, 23}
  {0x1fffdc, 21}
  {0x3fffd8, 22}
  {0x7fffe5, 23}
  {0x3fffd9, 22}
  {0x7fffe6, 23}
  {0x7fffe7, 23}
  {0xffffef, 24}
  {0x3fffda, 22}
  {0x1fffdd, 21}
  {0xfffe9, 20}
  {0x3fffdb, 22}
  {0x3fffdc, 22}
  {0x7fffe8, 23}
  {0x7fffe9, 23}
  {0x1fffde, 21}
  {0x7fffea, 23}
  {0x3fffdd, 22}
  {0x3fffde, 22}
  {0xfffff0, 24}
  {0x1fffdf, 21}
  {0x3fffdf, 22}
  {0x7fffeb, 23}
  {0x7fffec, 23}
  {0x1fffe0, 21}
  {0x1fffe1, 21}
  {0x3fffe0, 22}
  {0x1fffe2, 21}
  {0x7fffed, 23}
  {0x3fffe1, 22}
  {0x7fffee, 23}
  {0x7fffef, 23}
  {0xfffea, 20}
  {0x3fffe2, 22}
  {0x3fffe3, 22}
  {0x3fffe4, 22}
  {0x7ffff0, 23}
  {0x3fffe5, 22}
  {0x3fffe6, 22}
  {0x7ffff1, 23}
  {0x3ffffe0, 26}
  {0x3ffffe1, 26}
  {0xfffeb, 20}
  {0x7fff1, 19}
  {0x3fffe7, 22}
  {0x7ffff2, 23}
  {0x3fffe8, 22}
  {0x1ffffec, 25}
  {0x3ffffe2, 26}
  {0x3ffffe3, 26}
  {0x3ffffe4, 26}
  {0x7ffffde, 27}
  {0x7ffffdf, 27}
  {0x3ffffe5, 26}
  {0xfffff1, 24}
  {0x1ffffed, 25}
  {0x7fff2, 19}
  {0x1fffe3, 21}
  {0x3ffffe6, 26}
  {0x7ffffe0, 27}
  {0x7ffffe1, 27}
  {0x3ffffe7, 26}
  {0x7ffffe2, 27}
  {0xfffff2, 24}
  {0x1fffe4, 21}
  {0x1fffe5, 21}
  {0x3ffffe8, 26}
  {0x3ffffe9, 26}
  {0xffffffd, 28}
  {0x7ffffe3, 27}
  {0x7ffffe4, 27}
  {0x7ffffe5, 27}
  {0xfffec, 20}
  {0xfffff3, 24}
  {0xfffed, 20}
  {0x1fffe6, 21}
  {0x3fffe9, 22}
  {0x1fffe7, 21}
  {0x1fffe8, 21}
  {0x7ffff3, 23}
  {0x3fffea, 22}
  {0x3fffeb, 22}
  {0x1ffffee, 25}
  {0x1ffffef, 25}
  {0xfffff4, 24}
  {0xfffff5, 24}
  {0x3ffffea, 26}
  {0x7ffff4, 23}
  {0x3ffffeb, 26}
  {0x7ffffe6, 27}
  {0x3ffffec, 26}
  {0x3ffffed, 26}
  {0x7ffffe7, 27}
  {0x7ffffe8, 27}
  {0x7ffffe9, 27}
  {0x7ffffea, 27}
  {0x7ffffeb, 27}
  {0xffffffe, 28}
  {0x7ffffec, 27}
  {0x7ffffed, 27}
  {0x7ffffee, 27}
  {0x7ffffef, 27}
  {0x7fffff0, 27}
  {0x3ffffee, 26}
  {0x3fffffff, 30}
}

-- Index de la table statique, construits une fois au chargement.
static_name_index = {}
static_exact_index = {}
for i = 1, #STATIC_TABLE
  name = STATIC_TABLE[i][1]
  value = STATIC_TABLE[i][2]
  static_name_index[name] = i unless static_name_index[name]
  static_exact_index["#{name}\0#{value}"] = i

-- Arbre de décodage Huffman, construit à la première utilisation puis mémoïsé.
_huffman_root = nil
huffman_tree = ->
  return _huffman_root if _huffman_root
  root = {}
  for sym = 0, 256
    entry = HUFFMAN_TABLE[sym + 1]
    code = entry[1]
    bits = entry[2]
    node = root
    for i = bits - 1, 0, -1
      b = bit.band(bit.rshift(code, i), 1)
      child = node[b]
      unless child
        child = {}
        node[b] = child
      node = child
    node.sym = sym
  _huffman_root = root
  root

--- Décode une chaîne littérale Huffman (RFC 7541 §5.2).
-- @tparam string s       Octets encodés.
-- @tparam number max_len Longueur maximale acceptée en sortie.
-- @treturn string|nil    Chaîne décodée, ou nil + raison.
huffman_decode = (s, max_len) ->
  out = {}
  node = huffman_tree!
  pending = 0
  pending_ones = true
  for i = 1, #s
    byte = s\byte i
    for b = 7, 0, -1
      v = bit.band(bit.rshift(byte, b), 1)
      node = node[v]
      return nil, "huffman_invalid_code" unless node
      pending += 1
      pending_ones = false if v == 0
      if node.sym != nil
        sym = node.sym
        return nil, "huffman_eos" if sym == 256
        out[#out + 1] = string.char sym
        return nil, "string_too_long" if max_len and #out > max_len
        node = huffman_tree!
        pending = 0
        pending_ones = true
  if node != huffman_tree!
    -- Le reliquat doit être un préfixe du code EOS : au plus 7 bits, tous à 1.
    return nil, "huffman_invalid_padding" if pending > 7 or not pending_ones
  table.concat out

--- Décode un entier à préfixe (RFC 7541 §5.1).
-- @tparam string s           Bloc d'octets.
-- @tparam number pos         Position de départ (1-based).
-- @tparam number prefix_bits Nombre de bits du préfixe.
-- @treturn number|nil Valeur, position suivante, ou nil + nil + raison.
decode_integer = (s, pos, prefix_bits) ->
  return nil, nil, "truncated_integer" if pos > #s
  mask = bit.lshift(1, prefix_bits) - 1
  value = bit.band(s\byte(pos), mask)
  pos += 1
  return value, pos, nil if value < mask
  shift = 0
  cont = 0
  while true
    return nil, nil, "truncated_integer" if pos > #s
    b = s\byte pos
    pos += 1
    cont += 1
    return nil, nil, "integer_too_long" if cont > 5
    value += bit.lshift(bit.band(b, 0x7f), shift)
    return nil, nil, "integer_too_long" if value > 0x7fffffff
    shift += 7
    break if bit.band(b, 0x80) == 0
  value, pos, nil

--- Décode une chaîne littérale (RFC 7541 §5.2), Huffman ou brute.
-- @tparam string s       Bloc d'octets.
-- @tparam number pos     Position de départ (1-based).
-- @tparam number max_len Longueur maximale acceptée.
-- @treturn string|nil Chaîne, position suivante, ou nil + nil + raison.
decode_string = (s, pos, max_len) ->
  return nil, nil, "truncated_string" if pos > #s
  huffman = bit.band(s\byte(pos), 0x80) != 0
  len, pos, err = decode_integer s, pos, 7
  return nil, nil, err if err
  return nil, nil, "string_too_long" if max_len and len > max_len
  return nil, nil, "truncated_string" if pos + len - 1 > #s
  raw = s\sub pos, pos + len - 1
  pos += len
  if huffman
    decoded, derr = huffman_decode raw, max_len
    return nil, nil, derr if derr
    return decoded, pos, nil
  raw, pos, nil

--- Cherche une entrée (statique puis dynamique) par index HPACK.
-- @tparam table decoder Décodeur.
-- @tparam number index  Index 1-based (1..61 statique, 62+ dynamique).
-- @treturn string|nil Nom, ou nil si l'index est hors table.
table_entry = (decoder, index) ->
  if index >= 1 and index <= #STATIC_TABLE
    return STATIC_TABLE[index][1], STATIC_TABLE[index][2]
  di = index - #STATIC_TABLE
  entry = decoder.entries[di]
  return nil unless entry
  entry[1], entry[2]

--- Évince les entrées les plus anciennes jusqu'à respecter max_size.
evict = (decoder) ->
  while decoder.size > decoder.max_size and #decoder.entries > 0
    last = table.remove decoder.entries
    decoder.size -= last[3]

--- Ajoute une entrée en tête de table dynamique puis évince si nécessaire.
-- Une entrée plus grande que la table vide la table et n'est pas conservée.
add_dynamic = (decoder, name, value) ->
  entry_size = #name + #value + 32
  table.insert decoder.entries, 1, { name, value, entry_size }
  decoder.size += entry_size
  evict decoder

--- Décode un littéral (nom indexé ou littéral, valeur littérale).
-- @treturn string|nil Nom, valeur, position suivante, ou nil×3 + raison.
decode_literal = (decoder, block, pos, prefix_bits) ->
  idx, pos, err = decode_integer block, pos, prefix_bits
  return nil, nil, nil, err if err
  name = nil
  if idx == 0
    name, pos, err = decode_string block, pos, decoder.max_header_size
    return nil, nil, nil, err if err
  else
    name = table_entry decoder, idx
    return nil, nil, nil, "index_out_of_range" unless name
  value, pos, err = decode_string block, pos, decoder.max_header_size
  return nil, nil, nil, err if err
  name, value, pos, nil

--- Ajoute un en-tête décodé en vérifiant le plafond de taille de liste.
append_header = (decoder, headers, name, value) ->
  decoder.header_size += #name + #value + 32
  return nil, "header_list_too_large" if decoder.header_size > decoder.max_header_size
  headers[#headers + 1] = { name, value }
  true

--- Crée un décodeur HPACK pour une connexion.
-- @tparam table opts {max_table_size: number, max_header_size: number}.
-- @treturn table Décodeur avec état (table dynamique propre à la connexion).
new_decoder = (opts = {}) ->
  max_size = opts.max_table_size or 4096
  {
    entries: {}
    size: 0
    max_size: max_size
    allowed_max_size: max_size
    max_header_size: opts.max_header_size or 16384
    header_size: 0
  }

--- Décode un bloc d'en-têtes HPACK complet.
-- @tparam table decoder Décodeur de la connexion.
-- @tparam string block  Bloc d'en-têtes (HEADERS + CONTINUATION concaténés).
-- @treturn table|nil Liste de {name, value}, ou nil + raison.
decode = (decoder, block) ->
  headers = {}
  decoder.header_size = 0
  pos = 1
  seen_header = false
  while pos <= #block
    b = block\byte pos
    if bit.band(b, 0x80) != 0
      -- Champ indexé.
      idx, pos, err = decode_integer block, pos, 7
      return nil, err if err
      return nil, "index_zero" if idx == 0
      name, value = table_entry decoder, idx
      return nil, "index_out_of_range" unless name
      ok, aerr = append_header decoder, headers, name, value
      return nil, aerr unless ok
      seen_header = true
    elseif bit.band(b, 0x40) != 0
      -- Littéral avec indexation incrémentale.
      name, value, pos, err = decode_literal decoder, block, pos, 6
      return nil, err if err
      add_dynamic decoder, name, value
      ok, aerr = append_header decoder, headers, name, value
      return nil, aerr unless ok
      seen_header = true
    elseif bit.band(b, 0x20) != 0
      -- Dynamic table size update (§6.3) : uniquement en tête de bloc.
      return nil, "dynamic_table_size_update_invalid" if seen_header
      size, pos, err = decode_integer block, pos, 5
      return nil, err if err
      return nil, "dynamic_table_size_update_too_large" if size > decoder.allowed_max_size
      decoder.max_size = size
      evict decoder
    else
      -- Littéral sans indexation (0000) ou jamais indexé (0001).
      name, value, pos, err = decode_literal decoder, block, pos, 4
      return nil, err if err
      ok, aerr = append_header decoder, headers, name, value
      return nil, aerr unless ok
      seen_header = true
  headers

--- Encode un entier à préfixe (RFC 7541 §5.1).
-- @tparam number value       Valeur positive.
-- @tparam number prefix_bits Nombre de bits du préfixe.
-- @tparam number flags       Bits de poids fort de l'octet initial.
-- @treturn string Octets encodés.
encode_integer = (value, prefix_bits, flags) ->
  max = bit.lshift(1, prefix_bits) - 1
  return string.char(bit.bor(flags, value)) if value < max
  parts = { string.char(bit.bor(flags, max)) }
  value -= max
  while value >= 128
    parts[#parts + 1] = string.char(bit.bor(bit.band(value, 0x7f), 0x80))
    value = bit.rshift(value, 7)
  parts[#parts + 1] = string.char value
  table.concat parts

--- Encode une chaîne littérale sans Huffman (RFC 7541 §5.2).
encode_string = (s) -> encode_integer(#s, 7, 0) .. s

--- Encode une liste d'en-têtes HPACK (sans Huffman, sans indexation dynamique).
-- Les couples {name, value} sont émis indexés s'ils existent tels quels dans
-- la table statique, sinon en littéral sans indexation (nom indexé si connu).
-- @tparam table headers Liste de {name, value}.
-- @treturn string Bloc d'en-têtes.
encode = (headers) ->
  parts = {}
  for pair in *headers
    name = pair[1]
    value = pair[2]
    exact = static_exact_index["#{name}\0#{value}"]
    if exact
      parts[#parts + 1] = string.char(bit.bor(0x80, exact))
    else
      name_idx = static_name_index[name] or 0
      parts[#parts + 1] = encode_integer name_idx, 4, 0
      parts[#parts + 1] = encode_string name if name_idx == 0
      parts[#parts + 1] = encode_string value
  table.concat parts

--- Retourne la valeur d'un en-tête (première occurrence).
-- @tparam table headers Liste de {name, value}.
-- @tparam string name   Nom recherché.
-- @treturn string|nil Valeur, ou nil si absente.
header_value = (headers, name) ->
  for pair in *headers
    return pair[2] if pair[1] == name
  nil

{
  :STATIC_TABLE
  :HUFFMAN_TABLE
  :new_decoder
  :decode
  :encode
  :encode_integer
  :decode_integer
  :decode_string
  :huffman_decode
  :header_value
}
