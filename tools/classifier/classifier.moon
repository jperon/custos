#!/usr/bin/env moon
-- tools/classifier/classifier.moon
-- Outil autonome (Docker) de classification de noms de domaines.
--
-- Pipeline :
--   1. Découvre les catégories disponibles via `ls <lists_dir>/*.txt`.
--   2. Lit un fichier texte de domaines fourni par l'utilisateur.
--   3. Interroge une IA (OpenRouter) pour classer chaque domaine dans une ou
--      plusieurs catégories EXISTANTES.
--   4. Ajoute chaque domaine aux fichiers <lists_dir>/<cat>.txt (dédup + tri).
--   5. Pour chaque domaine d'entrée, charge le site (Playwright via browse.py),
--      détecte les domaines tiers contactés et répète 3–4 sur eux (avec le
--      contexte « contactés en chargeant <site> »).
--   6. Compile les <lists_dir>/*.txt en .bin compatibles custos (mêmes hashs
--      xxh64 que src/filter/updater.moon).
--   7. Commit git automatique (pas de push).
--
-- Usage :
--   moon classifier.moon <domains-file> [options]
-- Options :
--   --lists-dir DIR   Répertoire des listes .txt        (défaut : lists)
--   --bin-dir DIR     Répertoire de sortie des .bin      (défaut : = lists-dir)
--   --model NAME      Modèle OpenRouter                  (défaut : openrouter/free)
--   --no-browse       Ne pas naviguer (étape 5)
--   --no-bin          Ne pas générer les .bin (étape 6)
--   --no-commit       Ne pas committer (étape 7)
--
-- Variables d'environnement (chargées aussi depuis un fichier .env, cf. plus bas) :
--   CLASSIFIER_API_URL  Endpoint chat/completions (défaut : OpenRouter)
--   CLASSIFIER_API_KEY  Clé API (repli : OPENROUTER_API_KEY)
--   CLASSIFIER_MODEL    Modèle(s) par défaut, séparés par des virgules → round-robin
--                       (bascule sur 429) ; repli openrouter/free ; --model prime
--   CLASSIFIER_ENV      Chemin du fichier .env à charger (défaut : ./.env)
--   CUSTOS_LUA          Répertoire lua/ du projet (pour ffi_xxhash/parse_domains)

-- ── Répertoires & package.path (AVANT tout require local) ─────────

--- Répertoire du script courant (déduit de arg[0]).
script_dir = do
  src = arg and arg[0] or "tools/classifier/classifier.moon"
  src\match("^(.*)/[^/]+$") or "."

-- json.lua est à côté du script.
package.path = "#{script_dir}/?.lua;#{package.path}"

-- Le lua/ compilé du projet fournit ffi_xxhash et filter.lib.parse_domains.
custos_lua = os.getenv("CUSTOS_LUA") or "#{script_dir}/../../lua"
package.path = "#{custos_lua}/?.lua;#{custos_lua}/?/init.lua;#{package.path}"

json = require "json"
-- is_valid : même validation de domaine que filter/updater (rejette IP, labels
-- avec tiret initial/final, TLD seul, etc.) → filtre le bruit du modèle.
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

load_dotenv os.getenv("CLASSIFIER_ENV") or ".env"

API_URL = env("CLASSIFIER_API_URL") or "https://openrouter.ai/api/v1/chat/completions"

--- Découpe une liste de modèles séparés par des virgules en table propre.
-- @tparam string|nil s ex. "modele-a, modele-b"
-- @treturn table liste des noms de modèles (espaces retirés, vides ignorés)
parse_models = (s) ->
  out = {}
  for m in (s or "")\gmatch "[^,]+"
    m = m\gsub("^%s+", "")\gsub("%s+$", "")
    out[#out + 1] = m if m != ""
  out

-- CLASSIFIER_MODEL peut contenir PLUSIEURS modèles séparés par des virgules :
-- classifier fait alors un round-robin et, en cas d'erreur 429 (rate limit), bascule
-- sur le modèle suivant plutôt que de réitérer sur le même.
DEFAULT_MODELS = parse_models env("CLASSIFIER_MODEL")
DEFAULT_MODELS = { "openrouter/free" } if #DEFAULT_MODELS == 0

-- Arrêt de sécurité : au-delà de ce nombre d'appels IA en échec consécutifs (réseau,
-- HTTP, JSON…), on stoppe tout le traitement. Réinitialisé par tout appel réussi.
MAX_CONSECUTIVE_ERRORS = 10
-- model_idx : position courante du round-robin sur la liste de modèles.
run_state = { consecutive: 0, aborted: false, model_idx: 1 }

-- ── Utilitaires ───────────────────────────────────────────────────

--- Quote une valeur pour un usage sûr dans une commande shell POSIX.
sh_quote = (s) -> "'" .. tostring(s)\gsub("'", "'\"'\"'") .. "'"

--- Écrit un message sur stderr.
warn = (msg) -> io.stderr\write "[classifier] #{msg}\n"

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

-- ── Étape 1 : découverte des catégories ───────────────────────────

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

-- ── Étape 2 : lecture des domaines d'entrée ───────────────────────

--- Lit un fichier 1 domaine/ligne (ignore vides et #commentaires).
-- @tparam string path
-- @treturn table|nil liste de domaines, ou nil + err
read_domains = (path) ->
  fh = io.open path, "r"
  return nil, "fichier introuvable : #{path}" unless fh
  domains, seen = {}, {}
  for line in fh\lines!
    d = line\match "^%s*([^%s#]+)"
    if d and not seen[d]
      seen[d] = true
      domains[#domains + 1] = d\lower!
  fh\close!
  domains

-- ── Étape 3 : appel à l'IA ────────────────────────────────────────

--- Construit le prompt (anglais) de classification.
-- @tparam table  domains    liste de domaines à classer
-- @tparam table  categories liste triée des catégories autorisées
-- @tparam string context    optionnel : site à l'origine des domaines
-- @treturn string
build_prompt = (domains, categories, context) ->
  cats = table.concat categories, ", "
  doms = table.concat domains, ", "
  lines = {
    "You are an expert in website classification. Your task is to determine which"
    "categories a domain name belongs to. A domain may belong to several categories."
    ""
    "You MUST only use categories from this exact list (ignore any other category):"
    cats
    ""
  }
  if context
    lines[#lines + 1] = "The following domains were contacted by the browser while loading the website \"#{context}\". Classify each by its own function (a CDN goes to a cdn-like category, ads to an ads-like category, etc.), not necessarily the category of \"#{context}\"."
    lines[#lines + 1] = ""
  lines[#lines + 1] = "Classify these domains: #{doms}"
  lines[#lines + 1] = ""
  lines[#lines + 1] = "Reply ONLY with a JSON object mapping each domain to an array of categories, e.g. {\"example.com\": [\"information\"]}. No prose, no explanation."
  table.concat lines, "\n"

--- Retire d'éventuelles clôtures Markdown ```json … ``` autour d'un contenu.
strip_fences = (s) ->
  s = s\gsub "^%s+", ""
  s = s\gsub "%s+$", ""
  if s\sub(1, 3) == "```"
    s = s\gsub "^```%w*%s*", ""
    s = s\gsub "%s*```$", ""
  s

--- Interroge l'API (OpenRouter ou compatible) et retourne {domaine: {cats…}}.
-- @tparam string prompt
-- @tparam string model
-- @tparam table  ignore_providers liste de providers à exclure (routage OpenRouter)
-- @treturn table|nil classification
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
  return nil, "JSON de classification invalide (provider #{provider}) : #{erri}" unless oki
  result, provider

-- ── Étape 4 : écriture dans les listes ────────────────────────────

--- Réécrit un fichier liste : déduplique (insensible à la casse), fusionne les
-- nouveaux domaines et TRIE le tout par ordre alphabétique (plus lisible pour un
-- relecteur humain). Les domaines sont normalisés en minuscules. Les commentaires
-- (#) sont conservés, regroupés en tête dans leur ordre d'origine ; les lignes
-- vides sont supprimées.
-- @tparam string path
-- @tparam table  new_doms nouveaux domaines (déjà minusculisés et validés)
-- @treturn number nb d'ajouts (domaines réellement nouveaux)
-- @treturn number nb de doublons retirés
rewrite_list = (path, new_doms) ->
  comments, domset, removed = {}, {}, 0
  fh = io.open path, "r"
  if fh
    for line in fh\lines!
      d = line\match "^%s*([^%s#]+)"
      if d
        key = d\lower!
        if domset[key]
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
  return added, removed unless ofh
  ofh\write table.concat(out, "\n")
  ofh\write "\n" if #out > 0
  ofh\close!
  added, removed

--- Ajoute la classification aux fichiers <dir>/<cat>.txt (dédup + ajout).
-- Ignore (warning) toute catégorie hors categories_set et tout domaine invalide.
-- @treturn table compteur { [cat]: nb_ajouts }
add_to_lists = (dir, classification, categories_set, added, removed_acc) ->
  added or= {}
  removed_acc or= {}
  -- Regroupe les domaines (validés) par catégorie.
  by_cat = {}
  for domain, cats in pairs classification
    continue unless type(cats) == "table"
    dl = domain\lower!
    unless is_valid dl
      warn "domaine invalide ignoré : #{domain}"
      continue
    for cat in *cats
      if categories_set[cat]
        by_cat[cat] or= {}
        by_cat[cat][#by_cat[cat] + 1] = dl
      else
        warn "catégorie inconnue ignorée : #{cat} (pour #{dl})"

  for cat, doms in pairs by_cat
    path = "#{dir}/#{cat}.txt"
    a, r = rewrite_list path, doms
    added[cat] = (added[cat] or 0) + a if a > 0
    removed_acc[cat] = (removed_acc[cat] or 0) + r if r > 0
  added

--- Cherche une catégorie hors périmètre dans une classification.
-- @treturn string|nil première catégorie inconnue rencontrée
first_unknown_category = (classification, categories_set) ->
  for _, cats in pairs classification
    continue unless type(cats) == "table"
    for cat in *cats
      return cat unless categories_set[cat]
  nil

--- Classe UN lot de domaines (avec retry/validation) et l'ajoute aux listes.
-- Si le moteur renvoie une catégorie inexistante, c'est le signe d'un moteur
-- sous-optimal : la réponse ENTIÈRE du lot est rejetée et la requête relancée en
-- excluant ce provider (jusqu'à opts.max_retries tentatives).
classify_batch = (batch, opts, added) ->
  prompt = build_prompt batch, opts.categories, opts.context
  models = opts.models
  nmodels = #models
  ignore = {}
  max = opts.max_retries or 3
  attempt = 1
  -- Round-robin : on reprend là où le lot précédent s'est arrêté.
  idx = run_state.model_idx
  advance = -> idx = (idx % nmodels) + 1
  while attempt <= max
    model = models[idx]
    classification, provider, status = call_ai prompt, model, ignore
    unless classification
      -- En échec, `provider` porte le message d'erreur.
      run_state.consecutive += 1
      if status == 429 and nmodels > 1
        warn "modèle #{model} : 429 (rate limit) → bascule sur le modèle suivant (#{run_state.consecutive}/#{MAX_CONSECUTIVE_ERRORS})"
        advance!
      else
        warn "modèle #{model} — tentative #{attempt}/#{max} échouée (#{run_state.consecutive}/#{MAX_CONSECUTIVE_ERRORS}) : #{provider}"
      if run_state.consecutive >= MAX_CONSECUTIVE_ERRORS
        run_state.aborted = true
        warn "ARRÊT : #{MAX_CONSECUTIVE_ERRORS} erreurs consécutives — traitement interrompu"
        return false
      attempt += 1
      continue

    -- Appel abouti (réponse exploitable) → on réinitialise le compteur d'erreurs.
    run_state.consecutive = 0

    bad = first_unknown_category classification, opts.categories_set
    if bad
      warn "catégorie inconnue « #{bad} » renvoyée par #{provider} → réponse rejetée, on relance sur un autre moteur (#{attempt}/#{max})"
      ignore[#ignore + 1] = provider if provider and provider != "?"
      advance!
      attempt += 1
      continue

    add_to_lists opts.lists_dir, classification, opts.categories_set, added, opts.removed
    -- Prochain lot : on démarre sur le modèle suivant (round-robin).
    run_state.model_idx = (idx % nmodels) + 1
    return true

  warn "abandon après #{max} tentative(s) : aucune réponse exploitable pour ce lot"
  false

--- Réécrit progress_file avec les domaines domains[start_idx..#domains] (1/ligne).
-- Sert à retirer les domaines déjà traités → reprise propre après interruption.
write_remaining = (path, domains, start_idx) ->
  fh = io.open path, "w"
  return unless fh
  for i = start_idx, #domains
    fh\write domains[i] .. "\n"
  fh\close!

--- Classe une liste de domaines en la découpant en lots de opts.batch_size,
-- chaque lot ayant sa propre boucle de retry/validation.
-- Si progress_file est fourni, il est réécrit après chaque lot RÉUSSI en n'y
-- laissant que les domaines pas encore traités (reprise sur interruption).
-- S'arrête si run_state.aborted (10 erreurs consécutives).
classify_and_add = (domains, opts, added, progress_file) ->
  return added if #domains == 0
  size = opts.batch_size or 50
  size = #domains if size <= 0
  total = #domains
  nbatches = math.ceil total / size
  for b = 1, nbatches
    break if run_state.aborted
    lo = (b - 1) * size + 1
    hi = math.min b * size, total
    batch = [domains[i] for i = lo, hi]
    warn "lot #{b}/#{nbatches} : #{#batch} domaine(s)" if nbatches > 1
    ok = classify_batch batch, opts, added
    -- Ne consomme l'entrée que si le lot a réellement été traité.
    write_remaining progress_file, domains, hi + 1 if ok and progress_file
  added

-- ── Étape 5 : navigation (domaines tiers contactés) ───────────────

--- Vrai si host == domain ou un sous-domaine de domain.
is_related = (host, domain) ->
  host == domain or host\sub(-(#domain + 1)) == ".#{domain}"

--- Navigue sur https://<domain> et retourne les domaines tiers contactés.
-- @treturn table liste (peut être vide)
browse = (domain) ->
  script = "#{script_dir}/browse.py"
  cmd = "python3 #{sh_quote(script)} #{sh_quote("https://#{domain}")} 2>/dev/null"
  fh = io.popen cmd
  unless fh
    warn "navigation impossible (popen) sur #{domain}"
    return {}
  raw = fh\read "*a"
  fh\close!
  hosts = nil
  ok = pcall -> hosts = json.decode raw
  unless ok and type(hosts) == "table"
    warn "sortie browse.py illisible pour #{domain}"
    return {}
  -- Exclut le domaine lui-même et ses sous-domaines.
  out, seen = {}, {}
  for h in *hosts
    hl = h\lower!
    continue if is_related hl, domain
    continue if seen[hl]
    seen[hl] = true
    out[#out + 1] = hl
  out

-- ── Étape 6 : compilation .bin (format custos) ────────────────────

--- Garantit que dir/.gitattributes marque les .bin comme binaires.
-- Sans cela git traite les .bin (hashs xxh64) comme du texte : diffs en mojibake
-- et, pire, risque de corruption si une conversion de fin de ligne s'applique.
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
-- @treturn number nb de .bin écrits, number nb d'erreurs
compile_bin = (lists_dir, bin_dir, categories) ->
  ffi = require "ffi"
  xxhash = require "ffi_xxhash"
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
    seen, hashes, n = {}, {}, 0
    for domain in *domains
      continue if seen[domain]
      seen[domain] = true
      n += 1
      hashes[n] = xxhash.xxh64 domain

    out = "#{bin_dir}/#{cat}.bin"

    -- Liste vide : on ne crée pas de .bin ex nihilo, mais on resynchronise un
    -- éventuel .bin périmé en le vidant (0 entrée).
    payload = ""
    if n > 0
      table.sort hashes, (a, b) -> a < b
      arr = ffi.new "uint64_t[?]", n
      for i = 1, n
        arr[i - 1] = hashes[i]
      payload = ffi.string arr, n * 8
    else
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

-- ── Étape 7 : commit git ──────────────────────────────────────────

--- Commit les modifications d'un dépôt git (pas de push).
-- Les opérations git sont exécutées DANS repo_dir (qui est lui-même le dépôt,
-- p.ex. le volume de listes monté) via `git -C`.
-- @tparam string repo_dir
-- @tparam number count
git_commit = (repo_dir, count) ->
  -- safe.directory='*' : le volume monté appartient à l'uid de l'hôte, pas à
  -- celui du conteneur → git refuserait sinon (« dubious ownership »).
  -- user.* : identité des commits automatiques (attribution claire). Surchargeable
  -- via GIT_AUTHOR_NAME / GIT_AUTHOR_EMAIL. Évite l'échec « tell me who you are »
  -- quand le conteneur n'a aucune identité git configurée.
  ident = "-c user.name=#{sh_quote os.getenv("GIT_AUTHOR_NAME") or "custos-classifier"} -c user.email=#{sh_quote os.getenv("GIT_AUTHOR_EMAIL") or "classifier@custos.local"}"
  git = "git -c safe.directory='*' #{ident} -C #{sh_quote repo_dir}"

  -- Vérifie d'abord que repo_dir est bien un dépôt git.
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
  date = os.date "%Y-%m-%d"
  msg = "classifier: #{count} domaine(s) classé(s) (#{date})"
  if os.execute("#{git} commit -m #{sh_quote(msg)}") == 0
    warn "commit créé : #{msg}"
  else
    warn "git commit a échoué"

-- ── Analyse des arguments ─────────────────────────────────────────

parse_args = (argv) ->
  opts = {
    lists_dir:   "lists"
    bin_dir:     nil
    models:      DEFAULT_MODELS
    max_retries: 3
    batch_size:  50
    browse:        true
    bin:           true
    commit:        true
    normalize_all: false
  }
  i = 1
  while argv[i]
    switch argv[i]
      when "--lists-dir"
        i += 1
        opts.lists_dir = argv[i]
      when "--bin-dir"
        i += 1
        opts.bin_dir = argv[i]
      when "--model"
        i += 1
        models = parse_models argv[i]
        opts.models = models if #models > 0
      when "--max-retries"
        i += 1
        opts.max_retries = tonumber(argv[i]) or 3
      when "--batch-size"
        i += 1
        opts.batch_size = tonumber(argv[i]) or 50
      when "--no-browse"
        opts.browse = false
      when "--no-bin"
        opts.bin = false
      when "--no-commit"
        opts.commit = false
      when "--normalize-all"
        opts.normalize_all = true
      else
        opts.input = argv[i] unless opts.input or argv[i]\sub(1, 2) == "--"
    i += 1
  opts.bin_dir or= opts.lists_dir
  opts

-- ── Point d'entrée ────────────────────────────────────────────────

main = (argv) ->
  opts = parse_args argv
  unless opts.input
    io.stderr\write "usage: classifier <domains-file> [--lists-dir DIR] [--bin-dir DIR] [--model NAME] [--batch-size N] [--max-retries N] [--no-browse] [--no-bin] [--no-commit] [--normalize-all]\n"
    os.exit 2

  categories_set, categories = list_categories opts.lists_dir
  if #categories == 0
    warn "aucune catégorie trouvée dans #{opts.lists_dir} (fichiers *.txt attendus)"
    os.exit 1
  warn "#{#categories} catégorie(s) disponible(s)"

  domains, err = read_domains opts.input
  unless domains
    warn err
    os.exit 1
  warn "#{#domains} domaine(s) à classer"
  if #opts.models > 1
    warn "#{#opts.models} modèles en round-robin : #{table.concat opts.models, ', '}"
  else
    warn "modèle : #{opts.models[1]}"

  added, removed = {}, {}
  ctx = {
    lists_dir: opts.lists_dir
    models: opts.models
    max_retries: opts.max_retries
    batch_size: opts.batch_size
    categories: categories
    categories_set: categories_set
    context: nil
    removed: removed
  }

  -- Étape 3-4 : classification directe des domaines fournis. Le fichier d'entrée
  -- est réécrit après chaque lot (domaines déjà traités retirés) → reprise propre.
  classify_and_add domains, ctx, added, opts.input

  -- Étape 5 : navigation + classification des domaines tiers (sauf si abandon).
  if opts.browse and not run_state.aborted
    for domain in *domains
      break if run_state.aborted
      contacted = browse domain
      if #contacted > 0
        warn "#{domain} → #{#contacted} domaine(s) tiers contacté(s)"
        sub_ctx = { k, v for k, v in pairs ctx }
        sub_ctx.context = domain
        classify_and_add contacted, sub_ctx, added

  -- Normalisation optionnelle de TOUTES les listes (dédup + tri en une passe).
  if opts.normalize_all
    for cat in *categories
      path = "#{opts.lists_dir}/#{cat}.txt"
      fh = io.open path, "r"
      continue unless fh
      fh\close!
      _, r = rewrite_list path, {}
      removed[cat] = (removed[cat] or 0) + r if r > 0

  -- Récapitulatif des ajouts.
  total = 0
  cats_sorted = [c for c in pairs added]
  table.sort cats_sorted
  for c in *cats_sorted
    warn "  + #{added[c]} → #{c}.txt"
    total += added[c]
  warn "total : #{total} ajout(s)"

  -- Récapitulatif des doublons retirés.
  total_removed = 0
  rem_sorted = [c for c in pairs removed]
  table.sort rem_sorted
  for c in *rem_sorted
    warn "  - #{removed[c]} doublon(s) → #{c}.txt"
    total_removed += removed[c]
  warn "total : #{total_removed} doublon(s) retiré(s)" if total_removed > 0

  -- Étape 6 : compilation .bin.
  if opts.bin
    written, errors = compile_bin opts.lists_dir, opts.bin_dir, categories
    warn ".bin : #{written} écrit(s), #{errors} erreur(s)"

  -- Étape 7 : commit (le dépôt git est le répertoire des listes lui-même).
  -- On commit même en cas d'abandon : le travail déjà fait est persisté et le
  -- fichier d'entrée ne contient plus que les domaines restant à traiter.
  if opts.commit
    git_commit opts.lists_dir, total

  -- Sortie en erreur si interruption par seuil d'erreurs (utile en CI/cron).
  os.exit 1 if run_state.aborted

main arg
