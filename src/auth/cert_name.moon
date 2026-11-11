-- src/auth/cert_name.moon
-- Validation des noms d'hôte destinés à un nom de fichier et au CN d'un
-- certificat. Le SNI est choisi par le client (non authentifié) : il ne doit
-- jamais contenir autre chose qu'un nom DNS simple ni permettre de sortir du
-- répertoire tmp/ (pas de « / », de « .. », d'octet nul ni de contrôle).

MAX_HOSTNAME_LEN = 253
MAX_LABEL_LEN = 63

--- Vrai si `name` est une adresse IPv4 littérale.
-- @tparam string name Nom à tester
-- @treturn boolean
is_ipv4_literal = (name) ->
  name\match("^%d+%.%d+%.%d+%.%d+$") != nil

--- Valide et normalise un nom DNS issu du SNI.
-- Refuse : longueur > 253, label > 63, caractère hors [a-z0-9.-], point en
-- tête/queue, label vide, tiret en tête/queue, joker, underscore, adresse IP
-- littérale, octet nul et caractère de contrôle.
-- @tparam string hostname Nom brut du ClientHello
-- @treturn string|nil Nom normalisé en minuscules, ou nil si refusé
sanitize_hostname = (hostname) ->
  return nil unless type(hostname) == "string"
  name = hostname\lower!
  return nil if #name == 0 or #name > MAX_HOSTNAME_LEN
  -- Jeu de caractères LDH seul : rejette aussi « / », NUL et les contrôles.
  return nil if name\find "[^a-z0-9.%-]"
  return nil if name\find("%.%.") or name\sub(1, 1) == "." or name\sub(-1) == "."
  return nil if is_ipv4_literal name
  for label in name\gmatch "[^.]+"
    return nil if #label > MAX_LABEL_LEN
    return nil if label\sub(1, 1) == "-" or label\sub(-1) == "-"
  name

--- Valide un nom de certificat interne : nom DNS validé OU adresse IP locale
-- (repli `getsockname` historique). Sert uniquement à composer un nom de
-- fichier : aucun « / », pas de traversée, pas d'octet de contrôle.
-- @tparam string name Nom DNS ou IP locale
-- @treturn string|nil Nom normalisé, ou nil si inutilisable
safe_cert_name = (name) ->
  return nil unless type(name) == "string"
  lname = name\lower!
  return nil if #lname == 0 or #lname > MAX_HOSTNAME_LEN
  -- Les adresses IPv6 locales contiennent « : » ; tout le reste est LDH.
  return nil if lname\find "[^a-z0-9.%-:]"
  return nil if lname\find("%.%.") or lname\sub(1, 1) == "." or lname\sub(-1) == "."
  lname

{ :sanitize_hostname, :safe_cert_name, :is_ipv4_literal, :MAX_HOSTNAME_LEN, :MAX_LABEL_LEN }
