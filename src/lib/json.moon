-- src/lib/json.moon
-- Encodeur/décodeur JSON minimal, sans dépendance, pour les instantanés de
-- métriques (écrits par worker_questions, lus par la page admin).
--
-- L'encodeur accepte nil, boolean, number, string et table. Une table dont
-- toutes les clés sont des entiers contigus 1..#t est un tableau, sinon un
-- objet. Le décodeur lève une erreur (`error`) sur une entrée invalide :
-- l'appelant traite alors le fichier corrompu comme absent.

EscapeMap = {
  '"':  '\\"'
  "\\": "\\\\"
  "\b": "\\b"
  "\f": "\\f"
  "\n": "\\n"
  "\r": "\\r"
  "\t": "\\t"
}

--- Encode une chaîne JSON (guillemets compris).
-- @tparam string s Chaîne brute
-- @treturn string Chaîne JSON
encode_string = (s) ->
  escaped = s\gsub '[%c"\\]', (c) ->
    EscapeMap[c] or string.format "\\u%04x", c\byte!
  '"' .. escaped .. '"'

--- Vrai si toutes les clés de `t` sont les entiers contigus 1..#t.
-- @tparam table t Table à tester
-- @treturn boolean
is_array = (t) ->
  n = #t
  return false if n == 0 and next(t) != nil
  count = 0
  for k in pairs t
    return false unless type(k) == "number"
    return false unless k >= 1 and k <= n and math.floor(k) == k
    count += 1
  count == n

encode_value = nil

--- Encode une valeur JSON.
-- @tparam any v Valeur (nil, boolean, number, string, table)
-- @tparam table stack Tables déjà visitées (détection de cycle)
-- @treturn string Représentation JSON
encode_value = (v, stack) ->
  switch type v
    when "nil"
      "null"
    when "boolean"
      v and "true" or "false"
    when "number"
      tostring v
    when "string"
      encode_string v
    when "table"
      return "null" if stack[v]
      stack[v] = true
      out = nil
      if is_array v
        parts = [(encode_value item, stack) for item in *v]
        out = "[" .. table.concat(parts, ",") .. "]"
      else
        keys = [k for k in pairs v]
        table.sort keys, (a, b) -> tostring(a) < tostring(b)
        parts = {}
        for k in *keys
          parts[#parts + 1] = encode_string(tostring(k)) .. ":" .. (encode_value v[k], stack)
        out = "{" .. table.concat(parts, ",") .. "}"
      stack[v] = nil
      out
    else
      "null"

--- Encode une valeur en JSON.
-- @tparam any v Valeur à encoder
-- @treturn string Chaîne JSON
encode = (v) ->
  encode_value v, {}

--- Construit un caractère UTF-8 depuis un point de code.
-- @tparam number cp Point de code Unicode
-- @treturn string Caractère encodé
utf8_char = (cp) ->
  if cp < 0x80
    string.char cp
  elseif cp < 0x800
    string.char 0xC0 + math.floor(cp / 0x40), 0x80 + cp % 0x40
  elseif cp < 0x10000
    string.char 0xE0 + math.floor(cp / 0x1000),
      0x80 + math.floor(cp / 0x40) % 0x40,
      0x80 + cp % 0x40
  else
    string.char 0xF0 + math.floor(cp / 0x40000),
      0x80 + math.floor(cp / 0x1000) % 0x40,
      0x80 + math.floor(cp / 0x40) % 0x40,
      0x80 + cp % 0x40

fail = (msg, pos) ->
  error "json: #{msg} (position #{pos})", 0

--- Saute les espaces JSON à partir de `i`.
-- @tparam string s Chaîne JSON
-- @tparam number i Position courante (1-based)
-- @treturn number Première position non blanche
skip_ws = (s, i) ->
  while true
    c = s\sub i, i
    if c == " " or c == "\t" or c == "\n" or c == "\r"
      i += 1
    else
      return i

parse_string = nil
parse_number = nil
parse_array = nil
parse_object = nil
parse_value  = nil

--- Décode une chaîne JSON (le curseur pointe sur le guillemet ouvrant).
-- @tparam string s Chaîne JSON
-- @tparam number i Position du guillemet ouvrant
-- @treturn string Chaîne décodée
-- @treturn number Position suivant le guillemet fermant
parse_string = (s, i) ->
  buf = {}
  i += 1
  while true
    jq = s\find '"', i, true
    jb = s\find "\\", i, true
    j = jq
    j = jb if jb and (not j or jb < j)
    fail "chaîne non terminée", i unless j
    buf[#buf + 1] = s\sub i, j - 1
    c = s\sub j, j
    return table.concat(buf), j + 1 if c == '"'
    e = s\sub j + 1, j + 1
    switch e
      when '"'
        buf[#buf + 1] = '"'
      when "\\"
        buf[#buf + 1] = "\\"
      when "/"
        buf[#buf + 1] = "/"
      when "b"
        buf[#buf + 1] = "\b"
      when "f"
        buf[#buf + 1] = "\f"
      when "n"
        buf[#buf + 1] = "\n"
      when "r"
        buf[#buf + 1] = "\r"
      when "t"
        buf[#buf + 1] = "\t"
      when "u"
        hex = s\sub j + 2, j + 5
        fail "échappement unicode invalide", j unless hex and hex\match "^%x%x%x%x$"
        cp = tonumber hex, 16
        -- Paire de substitution UTF-16 : \uD800-\uDBFF suivi de \uDC00-\uDFFF.
        if cp >= 0xD800 and cp <= 0xDBFF and s\sub(j + 6, j + 7) == "\\u"
          hex2 = s\sub j + 8, j + 11
          if hex2 and hex2\match "^%x%x%x%x$"
            cp2 = tonumber hex2, 16
            if cp2 >= 0xDC00 and cp2 <= 0xDFFF
              cp = 0x10000 + (cp - 0xD800) * 0x400 + (cp2 - 0xDC00)
              j += 6
        buf[#buf + 1] = utf8_char cp
        j += 4
      else
        fail "échappement invalide", j
    i = j + 2

--- Décode un nombre JSON.
-- @tparam string s Chaîne JSON
-- @tparam number i Position du premier caractère
-- @treturn number Nombre
-- @treturn number Position suivante
parse_number = (s, i) ->
  body = s\match "^-?%d+", i
  fail "nombre invalide", i unless body
  num = body
  j = i + #body
  if s\sub(j, j) == "."
    frac = s\match "^%.%d+", j
    fail "nombre invalide", j unless frac
    num ..= frac
    j += #frac
  if s\sub(j, j) == "e" or s\sub(j, j) == "E"
    exp = s\match "^[eE][+-]?%d+", j
    fail "exposant invalide", j unless exp
    num ..= exp
    j += #exp
  n = tonumber num
  fail "nombre invalide", i unless n
  n, j

--- Décode un tableau JSON.
-- @tparam string s Chaîne JSON
-- @tparam number i Position du crochet ouvrant
-- @treturn table Tableau décodé
-- @treturn number Position suivante
parse_array = (s, i) ->
  out = {}
  i = skip_ws s, i + 1
  return out, i + 1 if s\sub(i, i) == "]"
  while true
    v, i = parse_value s, i
    out[#out + 1] = v
    i = skip_ws s, i
    c = s\sub i, i
    if c == ","
      i = skip_ws s, i + 1
    elseif c == "]"
      return out, i + 1
    else
      fail "tableau invalide", i

--- Décode un objet JSON.
-- @tparam string s Chaîne JSON
-- @tparam number i Position de l'accolade ouvrante
-- @treturn table Objet décodé
-- @treturn number Position suivante
parse_object = (s, i) ->
  out = {}
  i = skip_ws s, i + 1
  return out, i + 1 if s\sub(i, i) == "}"
  while true
    fail "clé attendue", i unless s\sub(i, i) == '"'
    k, i = parse_string s, i
    i = skip_ws s, i
    fail "':' attendu", i unless s\sub(i, i) == ":"
    v, i = parse_value s, skip_ws(s, i + 1)
    out[k] = v
    i = skip_ws s, i
    c = s\sub i, i
    if c == ","
      i = skip_ws s, i + 1
    elseif c == "}"
      return out, i + 1
    else
      fail "objet invalide", i

--- Décode une valeur JSON.
-- @tparam string s Chaîne JSON
-- @tparam number i Position courante
-- @treturn any Valeur décodée
-- @treturn number Position suivante
parse_value = (s, i) ->
  i = skip_ws s, i
  c = s\sub i, i
  if c == '"'
    return parse_string s, i
  elseif c == "{"
    return parse_object s, i
  elseif c == "["
    return parse_array s, i
  elseif c == "t"
    fail "littéral invalide", i unless s\sub(i, i + 3) == "true"
    return true, i + 4
  elseif c == "f"
    fail "littéral invalide", i unless s\sub(i, i + 4) == "false"
    return false, i + 5
  elseif c == "n"
    fail "littéral invalide", i unless s\sub(i, i + 3) == "null"
    return nil, i + 4
  else
    fail "valeur invalide", i if c == ""
    return parse_number s, i

--- Décode une chaîne JSON.
-- @tparam string s Chaîne JSON
-- @treturn any Valeur décodée
decode = (s) ->
  fail "entrée non textuelle", 0 unless type(s) == "string"
  v, i = parse_value s, 1
  i = skip_ws s, i
  fail "caractères en trop", i if i <= #s
  v

{ :encode, :decode }
