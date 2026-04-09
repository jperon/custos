-- src/filter/lib/parse_domains.moon
-- Parsers de formats de listes de domaines (blocklists upstream).
-- Utilisé par filter/updater.moon pour normaliser différents formats de listes
-- en une suite de chaînes de domaines.
--
-- Formats supportés :
--   simple  : un domaine par ligne, # pour les commentaires
--   hosts   : 0.0.0.0 domain.com ou 127.0.0.1 domain.com (format /etc/hosts)
--   adblock : ||domain.com^ (format uBlock/AdBlock)

--- Vérifie qu'une chaîne ressemble à un nom de domaine valide.
-- Rejette les adresses IP, les entrées trop longues ou contenant
-- des caractères non autorisés.
-- @tparam string s Chaîne à valider
-- @treturn boolean
is_valid = (s) ->
  return false if #s == 0 or #s > 253
  return false if s\match "^%d+%.%d+%.%d+%.%d+$"  -- IPv4
  return false if s\match ":"                        -- IPv6
  return false unless s\match "%."                   -- au moins un point (pas de TLD seul)
  return false unless s\match "^[a-z0-9][a-z0-9._%-]*[a-z0-9]$"
  true

--- Parse le format "simple" : un domaine par ligne, # pour les commentaires.
-- Compatible avec les listes plain-text et les exports de Pi-hole.
-- @tparam string text Contenu brut de la liste
-- @treturn table      Tableau de domaines (strings)
parse_simple = (text) ->
  result = {}
  for line in text\gmatch "[^\n]+"
    domain = line\match "^%s*([^%s#]+)"
    continue unless domain
    domain = domain\lower!
    result[#result + 1] = domain if is_valid domain
  result

--- Parse le format "hosts" : entrées de type /etc/hosts.
-- Extrait le deuxième champ (le nom d'hôte) des lignes de la forme
-- "0.0.0.0 domain.com" ou "127.0.0.1 domain.com".
-- Ignore les entrées spéciales : localhost, 0.0.0.0, broadcasthost, ::1.
-- @tparam string text Contenu brut de la liste
-- @treturn table      Tableau de domaines (strings)
parse_hosts = (text) ->
  skip = { localhost: true, broadcasthost: true, ["0.0.0.0"]: true, ["::1"]: true, ["127.0.0.1"]: true }
  result = {}
  for line in text\gmatch "[^\n]+"
    line = line\match "^%s*(.-)%s*$"
    continue if line == "" or line\sub(1, 1) == "#"
    _, domain = line\match "^(%S+)%s+(%S+)"
    continue unless domain
    domain = domain\lower!
    continue if skip[domain]
    result[#result + 1] = domain if is_valid domain
  result

--- Parse le format "adblock" : règles ||domain.com^ (uBlock Origin / AdBlock).
-- Extrait uniquement les règles de blocage de domaines simples ;
-- ignore les règles CSS, les exceptions (@@) et les filtres complexes.
-- @tparam string text Contenu brut de la liste
-- @treturn table      Tableau de domaines (strings)
parse_adblock = (text) ->
  result = {}
  for line in text\gmatch "[^\n]+"
    domain = line\match "^||([^%^/|@%s]+)%^"
    continue unless domain
    domain = domain\lower!
    result[#result + 1] = domain if is_valid domain
  result

parsers = {
  simple:  parse_simple
  hosts:   parse_hosts
  adblock: parse_adblock
}

--- Sélectionne le bon parser selon le format et retourne les domaines extraits.
-- Si le format est inconnu, utilise "simple" par défaut.
-- @tparam string format "simple" | "hosts" | "adblock"
-- @tparam string text   Contenu brut téléchargé
-- @treturn table        Tableau de domaines (strings)
parse = (format, text) ->
  fn = parsers[format] or parse_simple
  fn text

{ :parse, :parse_simple, :parse_hosts, :parse_adblock, :is_valid }
