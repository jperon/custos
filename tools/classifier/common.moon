-- tools/classifier/common.moon
-- Helpers partagés entre les outils autonomes de gestion des listes
-- (classifier.moon, simplifier.moon) : chargement .env, appel IA OpenRouter,
-- (ré)écriture des listes .txt, compilation .bin custos, commit git.
--
-- Aucun de ces helpers ne dépend de l'outil appelant : ils sont importés via
--   common = require "common"
-- une fois que package.path contient le répertoire du script (où vit ce module)
-- ainsi que le lua/ compilé du projet (pour ffi_xxhash / filter.lib.parse_domains).

json = require "json"
{ :is_valid } = require "filter.lib.parse_domains"

-- ── Configuration (.env + variables d'environnement) ──────────────

dotenv = {}

--- Charge un fichier .env (lignes KEY=VALUE, # commentaires, quotes optionnelles).
-- Les variables réelles du process restent prioritaires (cf. env()).
load_dotenv = (path) ->
  fh = io.open path, "r"
  return unless fh
  for line in fh\lines!
    continue if line\match("^%s*#") or not line\match("%S")
    k, v = line\match "^%s*([%w_]+)%s*=%s*(.-)%s*$"
    if k
      v = v\gsub('^"(.*)"$', "%1")\gsub "^'(.*)'$", "%1"
      dotenv[k] = v
  fh\close!

--- Lit une variable : environnement réel d'abord, puis .env.
env = (name) -> os.getenv(name) or dotenv[name]

--- Découpe une liste de modèles séparés par des virgules en table propre.
-- @tparam string|nil s ex. "modele-a, modele-b"
-- @treturn table liste des noms de modèles (espaces retirés, vides ignorés)
parse_models = (s) ->
  out = {}
  for m in (s or "")\gmatch "[^,]+"
    m = m\gsub("^%s+", "")\gsub("%s+$", "")
    out[#out + 1] = m if m != ""
  out

-- ── Utilitaires ───────────────────────────────────────────────────

--- Quote une valeur pour un usage sûr dans une commande shell POSIX.
sh_quote = (s) -> "'" .. tostring(s)\gsub("'", "'\"'\"'") .. "'"

--- Écrit un message sur stderr. tag identifie l'outil appelant.
make_warn = (tag) -> (msg) -> io.stderr\write "[#{tag}] #{msg}\n"

--- Lit tout le contenu d'un fichier (nil si absent).
read_file = (path) ->
  fh = io.open path, "r"
  return nil unless fh
  data = fh\read "*a"
  fh\close!
  data

--- Crée ./tmp/ si nécessaire et retourne un chemin de fichier temporaire.
tmp_path = (name) ->
  os.execute "mkdir -p ./tmp"
  "./tmp/#{name}"

-- ── Découverte des catégories ─────────────────────────────────────

--- Liste les catégories disponibles dans dir (fichiers *.txt).
-- @tparam string dir
-- @treturn table set { [nom]: true }
-- @treturn table liste triée des noms
list_categories = (dir) ->
  fh = io.popen "ls -1 #{sh_quote(dir)}/*.txt 2>/dev/null"
  set, names = {}, {}
  if fh
    for line in fh\lines!
      name = line\match "([^/]+)%.txt$"
      if name
        set[name] = true
        names[#names + 1] = name
    fh\close!
  table.sort names
  set, names

-- ── Appel à l'IA (OpenRouter ou API OpenAI-compatible) ────────────

--- Retire d'éventuelles clôtures Markdown ```json … ``` autour d'un contenu.
strip_fences = (s) ->
  s = s\gsub "^%s+", ""
  s = s\gsub "%s+$", ""
  if s\sub(1, 3) == "```"
    s = s\gsub "^```%w*%s*", ""
    s = s\gsub "%s*```$", ""
  s

API_URL = env("CLASSIFIER_API_URL") or "https://openrouter.ai/api/v1/chat/completions"

--- Interroge l'API et retourne le contenu JSON décodé renvoyé par le modèle.
-- @tparam string prompt
-- @tparam string model
-- @tparam table  ignore_providers liste de providers à exclure (routage OpenRouter)
-- @treturn table|nil contenu JSON décodé
-- @treturn string|nil provider ayant répondu (ou message d'erreur si nil)
-- @treturn number|nil code HTTP en cas d'erreur applicative (ex. 429), sinon nil
call_ai = (prompt, model, ignore_providers) ->
  key = env("CLASSIFIER_API_KEY") or env("OPENROUTER_API_KEY")
  return nil, "clé API absente (CLASSIFIER_API_KEY ou OPENROUTER_API_KEY)" unless key and key != ""

  req = {
    model: model
    messages: { { role: "user", content: prompt } }
  }
  -- Exclut les providers déjà jugés sous-optimaux → force un autre moteur.
  if ignore_providers and #ignore_providers > 0
    req.provider = { ignore: ignore_providers }
  body = json.encode req

  req_file = tmp_path "request.json"
  fh = io.open req_file, "w"
  return nil, "écriture #{req_file} impossible" unless fh
  fh\write body
  fh\close!

  -- On NE met PAS --fail : on veut le corps d'erreur de l'API (JSON explicite) et
  -- le code HTTP. stdout = code HTTP (-w), corps → resp_file, stderr → err_file.
  resp_file = tmp_path "response.json"
  err_file  = tmp_path "curl.err"
  cmd = table.concat {
    "curl --silent --show-error --location --max-time 120"
    "-H #{sh_quote("Authorization: Bearer #{key}")}"
    "-H 'Content-Type: application/json'"
    "--data @#{sh_quote(req_file)}"
    "-o #{sh_quote(resp_file)}"
    "-w '%{http_code}'"
    sh_quote(API_URL)
    "2>#{sh_quote(err_file)}"
  }, " "

  pipe = io.popen cmd
  return nil, "popen curl échoué" unless pipe
  http_code = (pipe\read("*a") or "")\gsub("%s+", "")
  ok = pipe\close!

  curl_err = (read_file(err_file) or "")\gsub("%s+$", "")
  raw = read_file(resp_file) or ""

  -- Échec du process curl (réseau, DNS, timeout, TLS…) : code HTTP vide ou "000".
  unless ok and http_code != "" and http_code != "000"
    msg = curl_err != "" and curl_err or "erreur réseau/curl"
    return nil, "curl: #{msg}"

  -- Erreur HTTP applicative : on remonte le corps (souvent un JSON {error:{message}}).
  -- Le code HTTP est renvoyé en 3ᵉ valeur pour permettre au caller de gérer le 429.
  unless http_code\match "^2%d%d$"
    detail = raw != "" and raw\gsub("%s+", " ")\sub(1, 400) or curl_err
    return nil, "HTTP #{http_code}: #{detail}", tonumber(http_code)

  return nil, "réponse vide (HTTP #{http_code})" unless #raw > 0

  parsed = nil
  okd, errd = pcall -> parsed = json.decode raw
  return nil, "réponse JSON invalide (HTTP #{http_code}) : #{errd}\n#{raw}" unless okd

  provider = parsed.provider or "?"
  choice = parsed.choices and parsed.choices[1]
  content = choice and choice.message and choice.message.content
  return nil, "réponse OpenRouter sans content (provider #{provider})" unless content

  inner = strip_fences content
  result = nil
  oki, erri = pcall -> result = json.decode inner
  return nil, "JSON de réponse invalide (provider #{provider}) : #{erri}" unless oki
  result, provider

-- ── (Ré)écriture des listes .txt ──────────────────────────────────

--- Réécrit un fichier liste : déduplique (insensible à la casse), retire les
-- domaines de `drop` (set { [domaine_minuscule]: true }), fusionne `new_doms` et
-- TRIE le tout par ordre alphabétique. Les domaines sont normalisés en minuscules.
-- Les commentaires (#) sont conservés, regroupés en tête dans leur ordre d'origine ;
-- les lignes vides sont supprimées.
-- @tparam string path
-- @tparam table  new_doms nouveaux domaines (déjà minusculisés et validés)
-- @tparam table|nil drop  domaines à supprimer (set), p.ex. repliés vers un parent
-- @treturn number nb d'ajouts (domaines réellement nouveaux)
-- @treturn number nb de doublons retirés
-- @treturn number nb de domaines supprimés via `drop`
rewrite_list = (path, new_doms, drop) ->
  drop or= {}
  comments, domset, removed, dropped = {}, {}, 0, 0
  fh = io.open path, "r"
  if fh
    for line in fh\lines!
      d = line\match "^%s*([^%s#]+)"
      if d
        key = d\lower!
        if drop[key]
          dropped += 1
        elseif domset[key]
          removed += 1
        else
          domset[key] = true
      elseif line\match "%S"  -- ligne non vide sans domaine = commentaire
        comments[#comments + 1] = line
    fh\close!

  added = 0
  for d in *new_doms
    unless domset[d]
      domset[d] = true
      added += 1

  domains = [d for d in pairs domset]
  table.sort domains

  out = {}
  out[#out + 1] = c for c in *comments
  out[#out + 1] = d for d in *domains

  ofh = io.open path, "w"
  return added, removed, dropped unless ofh
  ofh\write table.concat(out, "\n")
  ofh\write "\n" if #out > 0
  ofh\close!
  added, removed, dropped

-- ── Compilation .bin (format custos) ──────────────────────────────

--- Garantit que dir/.gitattributes marque les .bin comme binaires.
-- @tparam string dir
ensure_gitattributes = (dir) ->
  path = "#{dir}/.gitattributes"
  rule = "*.bin binary"
  fh = io.open path, "r"
  if fh
    content = fh\read "*a"
    fh\close!
    return if content\match "%*%.bin%s+binary"
    out = io.open path, "a"
    return unless out
    out\write "\n" if #content > 0 and content\sub(-1) != "\n"
    out\write rule .. "\n"
    out\close!
  else
    out = io.open path, "w"
    return unless out
    out\write rule .. "\n"
    out\close!

--- Compile chaque <lists_dir>/<cat>.txt en <bin_dir>/<cat>.bin.
-- Réutilise le hachage du projet (ffi_xxhash + parse_domains) pour produire
-- des fichiers octet-pour-octet identiques à src/filter/updater.moon.
-- @tparam string  lists_dir
-- @tparam string  bin_dir
-- @tparam table   categories liste des catégories à (re)compiler
-- @tparam function warn      fonction de log (stderr)
-- @treturn number nb de .bin écrits, number nb d'erreurs
compile_bin = (lists_dir, bin_dir, categories, warn) ->
  ffi = require "ffi"
  bin48 = require "filter.lib.bin48"
  parse_domains = require "filter.lib.parse_domains"
  ffi.cdef "int rename(const char *oldpath, const char *newpath);" unless pcall -> ffi.C.rename

  os.execute "mkdir -p #{sh_quote(bin_dir)}"
  ensure_gitattributes bin_dir
  written, errors = 0, 0

  for cat in *categories
    txt = "#{lists_dir}/#{cat}.txt"
    fh = io.open txt, "r"
    continue unless fh
    data = fh\read "*a"
    fh\close!

    domains = parse_domains.parse "simple", data
    payload, n = bin48.pack_domains domains

    out = "#{bin_dir}/#{cat}.bin"

    -- Liste vide : on ne crée pas de .bin ex nihilo, mais on resynchronise un
    -- éventuel .bin périmé en le vidant (0 entrée).
    if n == 0
      existing = io.open out, "rb"
      if existing
        size = existing\seek "end"
        existing\close!
        continue if size == 0  -- déjà vide / rien à faire
      else
        continue               -- pas de .bin → ne rien créer pour une liste vide

    tmp = "#{out}.tmp"
    ofh = io.open tmp, "wb"
    unless ofh
      warn "écriture #{tmp} impossible"
      errors += 1
      continue
    ofh\write payload
    ofh\close!
    if ffi.C.rename(tmp, out) == 0
      written += 1
    else
      os.remove tmp
      warn "rename échoué : #{tmp} → #{out}"
      errors += 1

  written, errors

-- ── Commit git ────────────────────────────────────────────────────

--- Commit les modifications d'un dépôt git (pas de push).
-- @tparam string repo_dir dépôt (= répertoire des listes monté)
-- @tparam string msg      message de commit
-- @tparam function warn    fonction de log (stderr)
git_commit = (repo_dir, msg, warn) ->
  ident = "-c user.name=#{sh_quote os.getenv("GIT_AUTHOR_NAME") or "custos-classifier"} -c user.email=#{sh_quote os.getenv("GIT_AUTHOR_EMAIL") or "classifier@custos.local"}"
  git = "git -c safe.directory='*' #{ident} -C #{sh_quote repo_dir}"

  check = io.popen "#{git} rev-parse --is-inside-work-tree 2>/dev/null"
  is_repo = check and check\read("*a")
  check\close! if check
  unless is_repo and is_repo\match "true"
    warn "#{repo_dir} n'est pas un dépôt git — commit ignoré"
    return

  status = io.popen "#{git} status --porcelain 2>/dev/null"
  dirty = status and status\read("*a")
  status\close! if status
  unless dirty and dirty != ""
    warn "aucune modification à committer"
    return

  os.execute "#{git} add -A"
  if os.execute("#{git} commit -m #{sh_quote(msg)}") == 0
    warn "commit créé : #{msg}"
  else
    warn "git commit a échoué"

-- Arrêt de sécurité partagé : au-delà de ce nombre d'appels IA en échec
-- consécutifs, l'outil appelant stoppe son traitement.
MAX_CONSECUTIVE_ERRORS = 10

{
  :load_dotenv, :env, :parse_models
  :sh_quote, :make_warn, :read_file, :tmp_path
  :list_categories
  :strip_fences, :call_ai
  :rewrite_list
  :ensure_gitattributes, :compile_bin
  :git_commit
  :is_valid
  :MAX_CONSECUTIVE_ERRORS
}
