-- src/lib/shquote.moon
-- Échappement d'un argument pour insertion sûre dans une commande shell POSIX.
-- On entoure la valeur de quotes simples et on neutralise toute quote simple
-- interne via la séquence '\'' (ferme la quote, échappe un ', rouvre la quote).
-- Indispensable dès qu'une valeur de config ou un nom de fichier est interpolé
-- dans une chaîne passée à io.popen / os.execute.

--- Quote une chaîne pour un argument shell.
-- @tparam string s Valeur brute.
-- @treturn string Argument shell-safe, quotes simples comprises.
shquote = (s) ->
  s = tostring s
  "'" .. (s\gsub "'", "'\\''") .. "'"

{ :shquote }
