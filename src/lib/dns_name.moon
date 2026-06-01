-- src/lib/dns_name.moon
-- Encodage d'un nom de domaine au format DNS wire (RFC 1035 §3.1).
-- Partagé par forge_dns (réponses forgées) et dns_ede (réécriture CNAME).

--- Encode un nom de domaine en format wire DNS.
-- "example.com" → "\x07example\x03com\x00"
-- Les points finaux sont retirés avant encodage.
-- @tparam string name Nom de domaine en notation pointée.
-- @treturn string Nom binaire au format wire DNS.
encode_dns_name = (name) ->
  name = name\gsub "%.+$", ""
  parts = {}
  for label in name\gmatch "[^.]+"
    parts[#parts + 1] = string.char(#label) .. label
  table.concat(parts) .. "\x00"

{ :encode_dns_name }
