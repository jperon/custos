-- src/webui/util.moon
-- Helpers partagés des handlers de la webui admin : échappement HTML et
-- décodage des corps de formulaire urlencodés.

--- Échappe le texte destiné au contenu ou à un attribut HTML.
-- Le DSL `auth.html` n'échappe rien : tout handler qui injecte une valeur de
-- config ou de requête dans du HTML doit passer par cette fonction.
-- @tparam string|number|nil s Valeur à échapper (nil → "")
-- @treturn string Chaîne échappée (&, <, >, " et ')
esc = (s) ->
  return "" if s == nil
  s = tostring s
  (s\gsub "[&<>\"']", { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })

--- Décode un corps de formulaire urlencodé en table clé → valeur.
-- Les clés répétées gardent la dernière valeur ; `+` devient un espace et les
-- séquences `%xx` sont décodées.
-- @tparam string|nil body Corps brut (`a=1&b=x+y`) ou nil
-- @treturn table Table des champs (vide si body nil/vide)
parse_form = (body) ->
  return {} unless body
  out = {}
  dec = (s) -> (s\gsub "%%(%x%x)", (h) -> string.char tonumber h, 16)\gsub "+", " "
  for k, v in body\gmatch "([^&=]+)=([^&]*)"
    out[dec k] = dec v
  out

{ :esc, :parse_form }
