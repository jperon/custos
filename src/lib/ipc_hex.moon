-- src/lib/ipc_hex.moon
-- Helpers de format des messages IPC, partagés par les producteurs (workers) et
-- les consommateurs (worker_nft, nft_queue, mac_learner) : encodage
-- hexadécimal des octets bruts, champ IP fixe ip16, découpage des champs et
-- validation des timeouts nftables. Source unique : un écart émetteur/récepteur
-- casse silencieusement le pipe.

--- Encode une adresse IP brute sur 16 octets (convention IPC `ip16`).
-- IPv4 (4 octets) est suivie de 12 zéros ; IPv6 est copiée telle quelle.
-- Cette convention est consommée par mac_learner (`ip16_to_str`) et
-- `strip_target`.
-- @tparam string ip_raw Adresse brute (exactement 4 ou 16 octets)
-- @treturn string|nil 16 octets, ou nil si la longueur est invalide
encode_ip16 = (ip_raw) ->
  return nil unless type(ip_raw) == "string"
  return ip_raw if #ip_raw == 16
  return ip_raw .. "\0\0\0\0\0\0\0\0\0\0\0\0" if #ip_raw == 4
  nil

-- Table octet → 2 caractères hexadécimaux. `gsub` avec une TABLE ne crée ni
-- closure ni appel `string.format` par octet : le chemin IPC encode ~50 octets
-- par message (raison, rule_id, corrélateur nft) et chaque insertion nft en
-- encode 2 de plus — le coût mesuré de l'ancien encodage (closure + format par
-- octet) atteignait 12-40 % du hot path (docs/agents/perf.md §18).
HEX_BYTE = {}
for i = 0, 255
  HEX_BYTE[string.char(i)] = string.format "%02x", i

-- ── Cache de conversion (borné) ──────────────────────────────────────
-- Les mêmes valeurs reviennent des dizaines de fois par paquet : chaque ligne
-- nft encode `rule_id` + corrélateur (une ligne par set et par timeout depuis
-- les insertions groupées, 16 lignes avant ; cf. docs/agents/perf.md §29a), et
-- `rule_id`/raison sont identiques d'un paquet à l'autre.
-- 8 entrées maximum, purge complète au débordement : mémoire bornée à
-- 8 entrées × (256 + 512) o, aucune invalidation possible (les deux
-- fonctions sont pures : même entrée → même sortie). Mesure chiffrée :
-- docs/agents/perf.md §18.
CACHE_MAX_ENTRIES = 8
CACHE_MAX_INPUT   = 256

_hex_enc_cache = {}
_hex_enc_n     = 0
_hex_dec_cache = {}
_hex_dec_n     = 0

--- Encode une chaîne d'octets en hexadécimal minuscule.
-- @tparam string s Chaîne d'octets
-- @treturn string Représentation hexadécimale ("" si vide)
to_hex = (s) ->
  return "" unless s and #s > 0
  hit = _hex_enc_cache[s]
  -- Contrat : UNE seule valeur, comme le `(s\gsub ...)` parenthésé d'avant le
  -- cache. `nft_queue.build_line` place `to_hex corr` en DERNIER champ d'un
  -- constructeur de table : une deuxième valeur y ajouterait un 10e champ, et
  -- `worker_nft.parse_line` (exactement 9 champs) rejetterait alors TOUTES les
  -- insertions nft avec `field_count` (régression e2e T03/T74 : sets vides, puis
  -- SYN bloqué vers 10.42.0.50 d'où l'absence de logs SNI T121-T124b). Le
  -- compte de substitutions n'a aucun appelant : ne pas le rendre.
  return hit if hit
  out = (s\gsub ".", HEX_BYTE)
  if #s <= CACHE_MAX_INPUT
    if _hex_enc_n >= CACHE_MAX_ENTRIES
      _hex_enc_cache = {}
      _hex_enc_n = 0
    _hex_enc_cache[s] = out
    _hex_enc_n += 1
  out

-- Valeur hexadécimale d'un octet de code (nil si ce n'est pas un caractère
-- hexadécimal) : décodage par paires sans `sub`+`tonumber`+`string.char`
-- intermédiaires (cf. docs/agents/perf.md §18 : le décodage pèse ~50 % du
-- coût du tube question→réponse mesuré par le banc `make bench-hotpath`).
HEX_VAL = {}
for i = 0, 9
  HEX_VAL[string.byte("0") + i] = i
for i = 0, 5
  HEX_VAL[string.byte("a") + i] = 10 + i
  HEX_VAL[string.byte("A") + i] = 10 + i

--- Décode une chaîne hexadécimale en octets, avec validation.
-- Ordre des erreurs inchangé : longueur impaire d'abord, puis caractère non
-- hexadécimal (l'ancienne version validait par un motif avant de décoder).
-- @tparam string h Chaîne hexadécimale
-- @treturn string|nil Octets décodés
-- @treturn string|nil Code d'erreur ("hex_odd_length", "hex_invalid_chars")
from_hex = (h) ->
  return "", nil if not h or #h == 0
  hit = _hex_dec_cache[h]
  return hit, nil if hit
  n = #h
  return nil, "hex_odd_length"   if (n % 2) != 0
  out = {}
  j = 1
  i = 1
  while i <= n
    hi = HEX_VAL[h\byte(i)]
    lo = HEX_VAL[h\byte(i + 1)]
    return nil, "hex_invalid_chars" unless hi and lo
    out[j] = string.char(hi * 16 + lo)
    j += 1
    i += 2
  decoded = table.concat(out)
  if n <= CACHE_MAX_INPUT
    if _hex_dec_n >= CACHE_MAX_ENTRIES
      _hex_dec_cache = {}
      _hex_dec_n = 0
    _hex_dec_cache[h] = decoded
    _hex_dec_n += 1
  decoded, nil

--- Découpe une ligne IPC sur le séparateur "|", champs vides préservés.
-- @tparam string line Ligne IPC
-- @treturn table Liste des champs
split_fields = (line) ->
  out = {}
  i = 1
  while true
    j = line\find "|", i, true
    if j
      out[#out + 1] = line\sub i, j - 1
      i = j + 1
    else
      out[#out + 1] = line\sub i
      break
  out

-- Validation par octets plutôt que par motif Lua : ces prédicats tournent une
-- fois par message IPC (`decode_msg`) et `is_valid_timeout` une fois par LIGNE
-- nft (`nft_queue.sanitize_timeout`, 16 lignes par réponse) — mesuré 0,067 µs
-- par appel en motif contre 0,02 en boucle compilée (§26).
BYTE_0, BYTE_9 = 48, 57
BYTE_DOT, BYTE_COLON = 46, 58

--- Vrai si le caractère est un chiffre décimal (octet).
-- @tparam number b Octet
-- @treturn boolean
is_digit = (b) -> b >= BYTE_0 and b <= BYTE_9

--- Vrai si la chaîne a la forme d'une adresse IPv4 pointée
-- (`%d+%.%d+%.%d+%.%d+`, mêmes acceptations que l'ancien motif : aucune borne
-- de valeur ni de longueur de groupe).
-- @tparam string s Adresse textuelle
-- @treturn boolean
is_ipv4_str = (s) ->
  return false unless s and #s > 0
  groups = 1
  digits = 0
  i = 1
  n = #s
  while i <= n
    b = s\byte i
    if b == BYTE_DOT
      return false if digits == 0 or groups >= 4
      groups += 1
      digits = 0
    elseif is_digit b
      digits += 1
    else
      return false
    i += 1
  groups == 4 and digits > 0

--- Vrai si la chaîne ressemble à une adresse IPv6 (présence de ":").
-- @tparam string s Adresse textuelle
-- @treturn boolean
is_ipv6_str = (s) -> s and s\find ":", 1, true

--- Vrai si la chaîne a la forme aa:bb:cc:dd:ee:ff (17 caractères, colons aux
-- positions 3, 6, 9, 12, 15, chiffres hexadécimaux ailleurs).
-- @tparam string s Adresse MAC textuelle
-- @treturn boolean
is_valid_mac = (s) ->
  return false unless type(s) == "string" and #s == 17
  for i = 1, 17
    b = s\byte i
    if i % 3 == 0
      return false unless b == BYTE_COLON
    else
      return false unless HEX_VAL[b]
  true

--- Vrai si l'octet est une unité de timeout nftables (s m h d w).
-- @tparam number b Octet
-- @treturn boolean
is_timeout_unit = (b) -> b == 115 or b == 109 or b == 104 or b == 100 or b == 119

--- Valide un timeout nftables (ex. "30s", "2m", "1h", "5d", "1w", "60").
-- Mêmes acceptations que `^%d+[smhdw]?$` : chiffres, puis au plus une unité.
-- @tparam string t Valeur de timeout
-- @treturn boolean true si la valeur est acceptée par nft
is_valid_timeout = (t) ->
  return false unless type(t) == "string"
  n = #t
  return false unless n > 0 and n <= 16
  i = 1
  while i <= n
    break unless is_digit t\byte i
    i += 1
  return false if i == 1          -- aucun chiffre
  return true if i > n            -- chiffres seuls
  return false if i < n           -- reste de plus d'un caractère
  is_timeout_unit t\byte(i)

{ :encode_ip16, :to_hex, :from_hex, :split_fields, :is_valid_timeout,
  :is_ipv4_str, :is_ipv6_str, :is_valid_mac, :is_digit, :is_timeout_unit }
