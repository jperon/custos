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

--- Encode une chaîne d'octets en hexadécimal minuscule.
-- @tparam string s Chaîne d'octets
-- @treturn string Représentation hexadécimale ("" si vide)
to_hex = (s) ->
  return "" unless s and #s > 0
  (s\gsub ".", HEX_BYTE)

--- Décode une chaîne hexadécimale en octets, avec validation.
-- @tparam string h Chaîne hexadécimale
-- @treturn string|nil Octets décodés
-- @treturn string|nil Code d'erreur ("hex_odd_length", "hex_invalid_chars")
from_hex = (h) ->
  return "", nil if not h or #h == 0
  return nil, "hex_odd_length"   if (#h % 2) != 0
  return nil, "hex_invalid_chars" unless h\match "^[0-9a-fA-F]+$"
  out = {}
  for i = 1, #h, 2
    out[#out + 1] = string.char tonumber(h\sub(i, i + 1), 16)
  table.concat(out), nil

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

--- Vrai si la chaîne a la forme d'une adresse IPv4 pointée.
-- @tparam string s Adresse textuelle
-- @treturn boolean
is_ipv4_str = (s) -> s and s\match "^%d+%.%d+%.%d+%.%d+$"

--- Vrai si la chaîne ressemble à une adresse IPv6 (présence de ":").
-- @tparam string s Adresse textuelle
-- @treturn boolean
is_ipv6_str = (s) -> s and s\find ":", 1, true

--- Vrai si la chaîne a la forme aa:bb:cc:dd:ee:ff.
-- @tparam string s Adresse MAC textuelle
-- @treturn boolean
is_valid_mac = (s) -> s and s\match "^[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]$"

--- Valide un timeout nftables (ex. "30s", "2m", "1h", "5d", "1w", "60").
-- @tparam string t Valeur de timeout
-- @treturn boolean true si la valeur est acceptée par nft
is_valid_timeout = (t) ->
  return false unless type(t) == "string"
  return false unless #t > 0 and #t <= 16
  t\match("^%d+[smhdw]?$") ~= nil

{ :encode_ip16, :to_hex, :from_hex, :split_fields, :is_valid_timeout,
  :is_ipv4_str, :is_ipv6_str, :is_valid_mac }
