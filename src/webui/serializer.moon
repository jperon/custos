-- src/webui/serializer.moon
-- Sérialise une table Lua en code MoonScript évaluable et écrit la config de
-- manière atomique. Produit un fichier "{ ... }" (table MoonScript) cohérent
-- avec le format des config.moon écrits à la main, rechargeable par
-- moonscript.base.loadfile.

-- Détecte si une table est un tableau (clés 1..n contiguës, non vide).
is_array = (t) ->
  return false unless type(t) == "table"
  n = #t
  return false if n == 0
  for i = 1, n
    return false if t[i] == nil
  true

-- Mots réservés qui ne peuvent pas être utilisés comme clés nues `clé: valeur`
-- en MoonScript (mots-clés Lua + mots-clés propres à MoonScript).
RESERVED_KEYWORDS = { and:1, break:1, do:1, else:1, elseif:1, end:1, false:1,
                      for:1, ["function"]:1, goto:1, if:1, ["in"]:1, local:1, nil:1,
                      not:1, or:1, repeat:1, ["return"]:1, then:1, true:1, until:1,
                      while:1, class:1, extends:1, import:1, export:1, unless:1,
                      using:1, switch:1, when:1, with:1, continue:1 }

-- Sérialise une valeur en chaîne de code MoonScript.
-- indent : indentation courante (string de spaces)
serialize_value = (v, indent) ->
  t = type v
  if t == "string"
    -- string.format "%q" produit une chaîne entre guillemets valide aussi en
    -- MoonScript (mêmes échappements que Lua).
    return string.format "%q", v
  elseif t == "number" or t == "boolean"
    return tostring v
  elseif t == "table"
    inner = indent .. "  "
    if is_array v
      parts = [serialize_value(item, inner) for item in *v]
      return "{ " .. table.concat(parts, ", ") .. " }"
    else
      -- Table associative : trier les clés pour une sortie déterministe
      keys = [k for k in pairs v]
      table.sort keys, (a, b) -> tostring(a) < tostring(b)
      if #keys == 0
        return "{}"
      lines = {}
      for k in *keys
        key_str = if type(k) == "string" and k\match("^[a-zA-Z_][a-zA-Z0-9_]*$") and not RESERVED_KEYWORDS[k]
          k
        else
          "[" .. serialize_value(k, inner) .. "]"
        lines[#lines + 1] = inner .. key_str .. ": " .. serialize_value(v[k], inner)
      return "{\n" .. table.concat(lines, "\n") .. "\n" .. indent .. "}"
  else
    return "nil"

--- Sérialise une table de configuration en code MoonScript évaluable.
-- @tparam  table  cfg  Table de configuration
-- @treturn string      Code MoonScript ({ ... }\n)
serialize_config = (cfg) ->
  serialize_value(cfg, "") .. "\n"

--- Écrit la configuration dans un fichier de manière atomique.
-- Utilise un fichier temporaire + rename pour garantir l'atomicité.
-- @tparam  table      cfg   Table de configuration à écrire
-- @tparam  string     path  Chemin du fichier de destination
-- @treturn true|nil         true en cas de succès
-- @treturn nil|string       Message d'erreur
write_config = (cfg, path) ->
  tmp = path .. ".webui.new"
  fh, err = io.open tmp, "w"
  return nil, "impossible d'ouvrir #{tmp} : #{err}" unless fh
  fh\write serialize_config cfg
  fh\close!
  ok, rename_err = os.rename tmp, path
  return nil, "rename() échoué : #{tostring rename_err}" unless ok
  true

--- Charge la configuration depuis un fichier Lua ou MoonScript.
-- @tparam  string     path  Chemin du fichier de configuration
-- @treturn table|nil        Table de configuration, ou nil
-- @treturn nil|string       Message d'erreur
read_config = (path) ->
  -- Essayer d'abord moonscript.base (supporte .moon et .lua)
  ok_moon, moon_base = pcall require, "moonscript.base"
  if ok_moon and moon_base
    chunk, err = moon_base.loadfile path
    if chunk
      ok, result = pcall chunk
      return result, nil if ok and type(result) == "table"
  -- Fallback loadfile Lua standard
  fn, err = loadfile path
  return nil, err unless fn
  ok, result = pcall fn
  return nil, tostring(result) unless ok and type(result) == "table"
  result, nil

{ :serialize_config, :write_config, :read_config }
