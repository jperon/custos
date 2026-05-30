#!/usr/bin/env moonjit
-- src/classifier.moon
-- Outil CLI : classe des noms de domaines en catégories via l'API OpenRouter
-- (modèles « free »). Aucune dépendance Lua externe : la requête HTTP passe par
-- `curl` (io.popen) et le JSON est encodé/décodé par un mini-parseur pur Lua.
--
-- Usage :
--   OPENROUTER_API_KEY=... luajit lua/classifier.lua [options] domaine...
--   echo -e "google.com\nfsspx.news" | OPENROUTER_API_KEY=... luajit lua/classifier.lua
--
-- Options :
--   --model M           Modèle OpenRouter (défaut : openrouter/free)
--   --categories a,b,c  Liste de catégories (défaut : information,…,telephonie)
--   --endpoint URL      Endpoint chat/completions
--   --timeout N         Timeout curl en secondes (défaut : 60)
--   --out-dir DIR       Écrit aussi une liste DIR/<categorie>.txt par catégorie
--   --help              Affiche l'aide
--
-- Sortie : un objet JSON { "domaine": ["categorie", …], … } sur stdout.

DEFAULT_MODEL    = "openrouter/free"
DEFAULT_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_CATEGORIES = {
  "information", "moteur_de_recherche", "jeux", "publicite",
  "religieux", "mail", "telephonie"
}

-- Sentinelle représentant `null` JSON (distincte de `nil` Lua).
JSON_NULL = setmetatable {}, { __tostring: -> "null" }

-- ── Encodage JSON ─────────────────────────────────────────────────

--- Échappe une chaîne pour l'insérer dans un littéral JSON.
-- @tparam string s Chaîne brute
-- @treturn string Chaîne échappée (sans les guillemets englobants)
json_escape = (s) ->
  s = tostring s
  s = s\gsub "\\", "\\\\"
  s = s\gsub '"', '\\"'
  s = s\gsub "\n", "\\n"
  s = s\gsub "\r", "\\r"
  s = s\gsub "\t", "\\t"
  -- Autres caractères de contrôle → \u00XX
  s\gsub "[%z\1-\31]", (c) -> string.format "\\u%04x", c\byte!

--- Indique si une table est un tableau séquentiel (clés 1..n contiguës).
-- @tparam table t Table à tester
-- @treturn boolean true si séquence contiguë (ou table vide)
is_array = (t) ->
  n = 0
  for k in pairs t
    return false unless type(k) == "number"
    n += 1
  n == #t

--- Encode une valeur Lua en JSON (clés d'objet triées pour un rendu stable).
-- @tparam table|string|number|boolean|nil v Valeur à encoder
-- @treturn string Représentation JSON
json_encode = (v) ->
  switch type v
    when "nil" then "null"
    when "boolean" then v and "true" or "false"
    when "number" then tostring v
    when "string" then '"' .. json_escape(v) .. '"'
    when "table"
      return "null" if v == JSON_NULL
      if is_array v
        parts = {}
        for item in *v
          parts[#parts + 1] = json_encode item
        "[" .. table.concat(parts, ",") .. "]"
      else
        keys = {}
        for k in pairs v
          keys[#keys + 1] = k
        table.sort keys, (a, b) -> tostring(a) < tostring(b)
        parts = {}
        for k in *keys
          parts[#parts + 1] = '"' .. json_escape(tostring k) .. '":' .. json_encode v[k]
        "{" .. table.concat(parts, ",") .. "}"
    else "null"

-- ── Décodage JSON (descente récursive) ────────────────────────────

local parse_value, parse_object, parse_array

--- Encode un point de code Unicode en UTF-8.
-- @tparam number cp Point de code
-- @treturn string Octets UTF-8
utf8_encode = (cp) ->
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

--- Saute les espaces blancs à partir de la position i.
-- @tparam string s   Texte JSON
-- @tparam number i   Position courante
-- @treturn number    Première position non blanche
skip_ws = (s, i) ->
  while i <= #s
    c = s\sub i, i
    break unless c == " " or c == "\t" or c == "\n" or c == "\r"
    i += 1
  i

--- Parse une chaîne JSON (s[i] doit être un guillemet ouvrant).
-- @tparam string s Texte JSON
-- @tparam number i Position du guillemet ouvrant
-- @treturn string  Chaîne décodée
-- @treturn number  Position juste après le guillemet fermant
-- @raise En cas de chaîne non terminée ou d'échappement invalide
parse_string = (s, i) ->
  i += 1
  parts = {}
  while i <= #s
    c = s\sub i, i
    if c == '"'
      return table.concat(parts), i + 1
    elseif c == "\\"
      nc = s\sub i + 1, i + 1
      switch nc
        when '"' then parts[#parts + 1] = '"'
        when "\\" then parts[#parts + 1] = "\\"
        when "/" then parts[#parts + 1] = "/"
        when "b" then parts[#parts + 1] = "\b"
        when "f" then parts[#parts + 1] = "\f"
        when "n" then parts[#parts + 1] = "\n"
        when "r" then parts[#parts + 1] = "\r"
        when "t" then parts[#parts + 1] = "\t"
        when "u"
          hex = s\sub i + 2, i + 5
          code = tonumber hex, 16
          error "JSON: échappement \\u invalide" unless code
          i += 4
          -- Paire de substitution UTF-16 (high + low surrogate)
          if code >= 0xD800 and code <= 0xDBFF and s\sub(i + 2, i + 3) == "\\u"
            hex2 = s\sub i + 4, i + 7
            low = tonumber hex2, 16
            if low and low >= 0xDC00 and low <= 0xDFFF
              code = 0x10000 + (code - 0xD800) * 0x400 + (low - 0xDC00)
              i += 6
          parts[#parts + 1] = utf8_encode code
        else
          error "JSON: échappement invalide \\#{nc}"
      i += 2
    else
      parts[#parts + 1] = c
      i += 1
  error "JSON: chaîne non terminée"

--- Parse une valeur JSON quelconque.
-- @tparam string s Texte JSON
-- @tparam number i Position courante
-- @treturn any     Valeur décodée (JSON_NULL pour null)
-- @treturn number  Position juste après la valeur
parse_value = (s, i) ->
  i = skip_ws s, i
  c = s\sub i, i
  switch c
    when '"' then parse_string s, i
    when "{" then parse_object s, i
    when "[" then parse_array s, i
    when "t"
      error "JSON: littéral invalide" unless s\sub(i, i + 3) == "true"
      true, i + 4
    when "f"
      error "JSON: littéral invalide" unless s\sub(i, i + 4) == "false"
      false, i + 5
    when "n"
      error "JSON: littéral invalide" unless s\sub(i, i + 3) == "null"
      JSON_NULL, i + 4
    else
      num = s\match "^%-?%d+%.?%d*[eE]?[%+%-]?%d*", i
      if num and num != ""
        n = tonumber num
        error "JSON: nombre invalide" unless n
        return n, i + #num
      error "JSON: caractère inattendu '#{c}' (pos #{i})"

--- Parse un objet JSON (s[i] doit être '{').
-- @tparam string s Texte JSON
-- @tparam number i Position de l'accolade ouvrante
-- @treturn table   Table clé→valeur
-- @treturn number  Position juste après '}'
parse_object = (s, i) ->
  obj = {}
  i = skip_ws s, i + 1
  if s\sub(i, i) == "}"
    return obj, i + 1
  while true
    i = skip_ws s, i
    error "JSON: clé d'objet attendue" unless s\sub(i, i) == '"'
    key, ni = parse_string s, i
    i = skip_ws s, ni
    error "JSON: ':' attendu" unless s\sub(i, i) == ":"
    val, vi = parse_value s, i + 1
    obj[key] = val
    i = skip_ws s, vi
    c = s\sub i, i
    if c == ","
      i += 1
    elseif c == "}"
      return obj, i + 1
    else
      error "JSON: ',' ou '}' attendu"

--- Parse un tableau JSON (s[i] doit être '[').
-- @tparam string s Texte JSON
-- @tparam number i Position du crochet ouvrant
-- @treturn table   Séquence de valeurs
-- @treturn number  Position juste après ']'
parse_array = (s, i) ->
  arr = {}
  i = skip_ws s, i + 1
  if s\sub(i, i) == "]"
    return arr, i + 1
  while true
    val, vi = parse_value s, i
    arr[#arr + 1] = val
    i = skip_ws s, vi
    c = s\sub i, i
    if c == ","
      i += 1
    elseif c == "]"
      return arr, i + 1
    else
      error "JSON: ',' ou ']' attendu"

--- Décode un document JSON.
-- @tparam string s Texte JSON
-- @treturn any|nil Valeur décodée, ou nil en cas d'erreur
-- @treturn nil|string Message d'erreur
json_decode = (s) ->
  return nil, "entrée vide" unless s and #s > 0
  ok, val = pcall parse_value, s, 1
  return nil, tostring(val) unless ok
  val

-- ── Construction de la requête ────────────────────────────────────

--- Quote une valeur pour un usage sûr dans une commande shell POSIX.
-- @tparam string s Valeur à échapper
-- @treturn string Valeur entre quotes simples (échappement interne)
sh_quote = (s) ->
  "'" .. tostring(s)\gsub("'", "'\"'\"'") .. "'"

--- Construit l'invite (prompt) de classification.
-- @tparam table domains     Liste de noms de domaines
-- @tparam table|nil categories Catégories cibles (défaut : DEFAULT_CATEGORIES)
-- @treturn string           Invite à envoyer au modèle
build_prompt = (domains, categories) ->
  categories or= DEFAULT_CATEGORIES
  table.concat {
    "Tu es un expert en classification de sites web, chargé de déterminer à "
    "quelles catégories appartient un nom de domaine. Un même nom de domaine "
    "peut appartenir à plusieurs catégories. Réponds UNIQUEMENT par un objet "
    "JSON valide (sans texte ni bloc de code autour) dont chaque clé est un "
    "nom de domaine et chaque valeur le tableau des catégories correspondantes "
    "choisies STRICTEMENT parmi : "
    table.concat categories, ", "
    ". Si aucune catégorie ne convient, renvoie un tableau vide. Domaines à "
    "classer : "
    table.concat domains, ", "
    "."
  }

--- Construit le corps JSON de la requête chat/completions.
-- @tparam string model  Identifiant du modèle
-- @tparam string prompt Invite utilisateur
-- @treturn string       Corps JSON
build_payload = (model, prompt) ->
  table.concat {
    '{"model":"'
    json_escape model
    '","messages":[{"role":"user","content":"'
    json_escape prompt
    '"}]}'
  }

--- Construit la commande curl complète.
-- @tparam string payload  Corps JSON
-- @tparam string api_key  Clé API OpenRouter
-- @tparam string endpoint URL de l'endpoint
-- @tparam number timeout  Timeout en secondes
-- @treturn string         Commande shell
build_curl_cmd = (payload, api_key, endpoint, timeout) ->
  table.concat {
    "curl --silent --show-error --location --max-time "
    tostring timeout
    " -H " .. sh_quote "Authorization: Bearer #{api_key}"
    " -H " .. sh_quote "Content-Type: application/json"
    " -d " .. sh_quote payload
    " " .. sh_quote endpoint
  }

-- ── Appel HTTP (curl via io.popen) ────────────────────────────────

--- Envoie l'invite à OpenRouter et retourne la réponse brute.
-- @tparam string prompt Invite utilisateur
-- @tparam table|nil opts { api_key, model, endpoint, timeout }
-- @treturn string|nil   Corps brut de la réponse, ou nil en cas d'erreur
-- @treturn nil|string   Message d'erreur
request = (prompt, opts) ->
  opts or= {}
  api_key = opts.api_key or os.getenv "OPENROUTER_API_KEY"
  return nil, "OPENROUTER_API_KEY manquante" unless api_key and api_key != ""
  model    = opts.model or DEFAULT_MODEL
  endpoint = opts.endpoint or DEFAULT_ENDPOINT
  timeout  = opts.timeout or 60
  payload  = build_payload model, prompt
  cmd = build_curl_cmd payload, api_key, endpoint, timeout
  fh = io.popen cmd
  return nil, "io.popen a échoué" unless fh
  body = fh\read "*a"
  ok = fh\close!
  body or= ""
  return nil, "curl a échoué (réseau ou timeout)" unless ok and #body > 0
  body

-- ── Analyse de la réponse ─────────────────────────────────────────

--- Extrait le contenu du message de la réponse OpenRouter.
-- @tparam string raw Corps brut JSON
-- @treturn string|nil Contenu du message, ou nil en cas d'erreur
-- @treturn nil|string Message d'erreur
extract_content = (raw) ->
  data, err = json_decode raw
  return nil, "réponse JSON invalide : #{err}" unless data
  return nil, "réponse JSON invalide" unless type(data) == "table"
  if data.error
    msg = if type(data.error) == "table" then (data.error.message or "erreur API") else tostring data.error
    return nil, "erreur OpenRouter : #{msg}"
  choices = data.choices
  return nil, "réponse sans 'choices'" unless type(choices) == "table" and type(choices[1]) == "table"
  message = choices[1].message
  return nil, "réponse sans 'message'" unless type(message) == "table"
  content = message.content
  return nil, "message sans 'content' textuel" unless type(content) == "string"
  content

--- Retire un éventuel bloc de code Markdown (```json … ```).
-- @tparam string text Contenu brut du message
-- @treturn string     Texte JSON nu
strip_code_fences = (text) ->
  t = text\gsub("^%s+", "")\gsub "%s+$", ""
  inner = t\match "^```[%w]*%s*(.-)%s*```$"
  return inner if inner
  t

--- Parse la classification renvoyée par le modèle.
-- @tparam string content Contenu du message (éventuellement clôturé en ```)
-- @treturn table|nil     Table domaine→catégories, ou nil en cas d'erreur
-- @treturn nil|string    Message d'erreur
parse_classification = (content) ->
  json_text = strip_code_fences content
  data, err = json_decode json_text
  return nil, "classification JSON invalide : #{err}" unless data
  return nil, "la classification n'est pas un objet JSON" unless type(data) == "table" and not is_array(data)
  data

-- ── Pipeline de haut niveau ───────────────────────────────────────

--- Classe une liste de domaines via OpenRouter.
-- @tparam table domains Liste de noms de domaines
-- @tparam table|nil opts { api_key, model, endpoint, timeout, categories }
-- @treturn table|nil    Table domaine→catégories, ou nil en cas d'erreur
-- @treturn nil|string   Message d'erreur
-- @treturn table|nil    Métadonnées { raw, content } en cas de succès
classify = (domains, opts) ->
  opts or= {}
  return nil, "aucun domaine fourni" unless domains and #domains > 0
  prompt = build_prompt domains, opts.categories
  raw, err = request prompt, opts
  return nil, err unless raw
  content, cerr = extract_content raw
  return nil, cerr unless content
  result, perr = parse_classification content
  return nil, perr unless result
  result, nil, { :raw, :content }

-- ── Écriture des listes par catégorie ─────────────────────────────

--- Écrit une liste DIR/<categorie>.txt (un domaine par ligne, triée).
-- @tparam table result  Table domaine→catégories
-- @tparam string out_dir Répertoire de sortie
-- @treturn table        Chemins des fichiers écrits
write_lists = (result, out_dir) ->
  os.execute "mkdir -p #{sh_quote out_dir}"
  by_cat = {}
  for domain, cats in pairs result
    if type(cats) == "table"
      for c in *cats
        by_cat[c] or= {}
        by_cat[c][#by_cat[c] + 1] = domain
  written = {}
  cats = {}
  for cat in pairs by_cat
    cats[#cats + 1] = cat
  table.sort cats
  for cat in *cats
    doms = by_cat[cat]
    table.sort doms
    path = "#{out_dir}/#{cat}.txt"
    fh = io.open path, "w"
    continue unless fh
    lines = {}
    for d in *doms
      lines[#lines + 1] = d
    fh\write table.concat(lines, "\n"), "\n"
    fh\close!
    written[#written + 1] = path
  written

-- ── Interface en ligne de commande ────────────────────────────────

USAGE = [[Usage : OPENROUTER_API_KEY=... luajit lua/classifier.lua [options] domaine...

Options :
  --model M           Modèle OpenRouter (défaut : openrouter/free)
  --categories a,b,c  Catégories cibles séparées par des virgules
  --endpoint URL      Endpoint chat/completions
  --timeout N         Timeout curl en secondes (défaut : 60)
  --out-dir DIR       Écrit aussi DIR/<categorie>.txt par catégorie
  --help              Affiche cette aide

Sans domaine en argument, les domaines sont lus sur l'entrée standard
(un par ligne).]]

--- Découpe une chaîne CSV en table (valeurs nettoyées, vides ignorées).
-- @tparam string s Chaîne « a, b , c »
-- @treturn table   { "a", "b", "c" }
split_csv = (s) ->
  out = {}
  for item in tostring(s)\gmatch "[^,]+"
    v = item\gsub("^%s+", "")\gsub "%s+$", ""
    out[#out + 1] = v if v != ""
  out

--- Analyse les arguments de la ligne de commande.
-- @tparam table argv Table d'arguments (argv[1], argv[2], …)
-- @treturn table     Options analysées { domains, model, … }
parse_args = (argv) ->
  opts = { domains: {} }
  i = 1
  while argv[i]
    a = argv[i]
    switch a
      when "--model"
        i += 1
        opts.model = argv[i]
      when "--endpoint"
        i += 1
        opts.endpoint = argv[i]
      when "--categories"
        i += 1
        opts.categories = split_csv argv[i]
      when "--timeout"
        i += 1
        opts.timeout = tonumber argv[i]
      when "--out-dir"
        i += 1
        opts.out_dir = argv[i]
      when "--help", "-h"
        opts.help = true
      else
        opts.domains[#opts.domains + 1] = a
    i += 1
  opts

--- Lit des domaines depuis un descripteur de fichier (un par ligne).
-- @tparam table fh Descripteur ouvert (io.stdin par défaut)
-- @treturn table   Liste de domaines
read_domains = (fh) ->
  fh or= io.stdin
  out = {}
  for line in fh\lines!
    d = line\gsub("^%s+", "")\gsub "%s+$", ""
    out[#out + 1] = d if d != "" and not d\match "^#"
  out

--- Point d'entrée CLI.
-- @tparam table argv Arguments (typiquement la table globale `arg`)
-- @treturn number    Code de sortie (0 = succès)
main = (argv) ->
  opts = parse_args argv or {}
  if opts.help
    print USAGE
    return 0
  domains = opts.domains
  domains = read_domains! if #domains == 0
  if #domains == 0
    io.stderr\write "Aucun domaine fourni.\n#{USAGE}\n"
    return 1
  result, err, meta = classify domains, opts
  unless result
    io.stderr\write "ERREUR : #{err}\n"
    return 1
  io.write json_encode(result), "\n"
  if opts.out_dir
    written = write_lists result, opts.out_dir
    io.stderr\write "#{#written} liste(s) écrite(s) dans #{opts.out_dir}/\n"
  0

-- Exécution directe (et non `require`) : on lance la CLI.
if arg and arg[0] and arg[0]\match "classifier%.lua$"
  os.exit main arg

{
  :DEFAULT_MODEL, :DEFAULT_ENDPOINT, :DEFAULT_CATEGORIES, :JSON_NULL
  :json_escape, :json_encode, :json_decode, :utf8_encode
  :is_array, :sh_quote
  :build_prompt, :build_payload, :build_curl_cmd
  :request, :extract_content, :strip_code_fences, :parse_classification
  :classify, :write_lists
  :split_csv, :parse_args, :read_domains, :main
}
