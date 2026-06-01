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

-- json.lua et common.lua sont à côté du script.
package.path = "#{script_dir}/?.lua;#{package.path}"
-- Usage hors Docker (via `moon`, non précompilé) : permettre le chargement de
-- common.moon voisin.
if package.moonpath
  package.moonpath = "#{script_dir}/?.moon;#{package.moonpath}"

-- Le lua/ compilé du projet fournit ffi_xxhash et filter.lib.parse_domains.
custos_lua = os.getenv("CUSTOS_LUA") or "#{script_dir}/../../lua"
package.path = "#{custos_lua}/?.lua;#{custos_lua}/?/init.lua;#{package.path}"

common = require "common"
{ :load_dotenv, :env, :parse_models, :sh_quote, :read_file, :list_categories,
  :call_ai, :rewrite_list, :compile_bin, :git_commit, :is_valid,
  :MAX_CONSECUTIVE_ERRORS } = common
simplify = require "simplify"
category_descriptions = require "descriptions"
warn = common.make_warn "classifier"

-- ── Configuration (.env + variables d'environnement) ──────────────

load_dotenv os.getenv("CLASSIFIER_ENV") or ".env"

-- CLASSIFIER_MODEL peut contenir PLUSIEURS modèles séparés par des virgules :
-- classifier fait alors un round-robin et, en cas d'erreur 429 (rate limit), bascule
-- sur le modèle suivant plutôt que de réitérer sur le même.
DEFAULT_MODELS = parse_models env("CLASSIFIER_MODEL")
DEFAULT_MODELS = { "openrouter/free" } if #DEFAULT_MODELS == 0

-- model_idx : position courante du round-robin sur la liste de modèles.
run_state = { consecutive: 0, aborted: false, model_idx: 1 }

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
  doms = table.concat domains, ", "
  -- Liste des catégories, une par ligne, avec sa description si elle existe :
  -- « name: description » (sinon le seul nom). Les descriptions lèvent les
  -- ambiguïtés (p. ex. art_nude ≠ pornographie).
  cat_lines = {}
  for cat in *categories
    desc = category_descriptions[cat]
    cat_lines[#cat_lines + 1] = desc and "- #{cat}: #{desc}" or "- #{cat}"
  cats = table.concat cat_lines, "\n"
  lines = {
    "You are an expert in website classification. Your task is to determine which"
    "categories a domain name belongs to. A domain may belong to several categories."
    ""
    "You MUST only use categories from this exact list (ignore any other category)."
    "Each line is a category, optionally followed by a description clarifying its scope:"
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

-- ── Étape 4 : écriture dans les listes ────────────────────────────

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
  ok = pcall -> hosts = require("json").decode raw
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
    simplify:             true
    simplify_min_children: 3
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
      when "--no-simplify"
        opts.simplify = false
      when "--simplify-min-children"
        i += 1
        opts.simplify_min_children = tonumber(argv[i]) or 3
      else
        opts.input = argv[i] unless opts.input or argv[i]\sub(1, 2) == "--"
    i += 1
  opts.bin_dir or= opts.lists_dir
  opts

-- ── Point d'entrée ────────────────────────────────────────────────

main = (argv) ->
  opts = parse_args argv
  unless opts.input
    io.stderr\write "usage: classifier <domains-file> [--lists-dir DIR] [--bin-dir DIR] [--model NAME] [--batch-size N] [--max-retries N] [--no-browse] [--no-bin] [--no-commit] [--normalize-all] [--no-simplify] [--simplify-min-children N]\n"
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

  -- Étape 5bis : simplification des catégories enrichies AVANT la compilation
  -- .bin (suppression des sous-domaines redondants + repli IA vers le parent).
  -- On ne traite que les catégories réellement modifiées par cette exécution.
  if opts.simplify and not run_state.aborted
    touched = [c for c in pairs added]
    table.sort touched
    if #touched > 0
      warn "simplification de #{#touched} catégorie(s) enrichie(s)…"
      sctx = {
        lists_dir:    opts.lists_dir
        models:       opts.models
        min_children: opts.simplify_min_children
        batch_size:   30
        max_retries:  opts.max_retries
        samples:      5
        dry_run:      false
        warn:         common.make_warn "classifier/simplify"
        run_state:    { consecutive: 0, aborted: false, model_idx: 1 }
      }
      sres = simplify.simplify_categories touched, sctx
      warn "simplification : #{sres.parents} repli(s) IA, #{sres.redundant} redondants, #{sres.dropped} domaine(s) supprimé(s)"

  -- Étape 6 : compilation .bin.
  if opts.bin
    written, errors = compile_bin opts.lists_dir, opts.bin_dir, categories, warn
    warn ".bin : #{written} écrit(s), #{errors} erreur(s)"

  -- Étape 7 : commit (le dépôt git est le répertoire des listes lui-même).
  -- On commit même en cas d'abandon : le travail déjà fait est persisté et le
  -- fichier d'entrée ne contient plus que les domaines restant à traiter.
  if opts.commit
    date = os.date "%Y-%m-%d"
    git_commit opts.lists_dir, "classifier: #{total} domaine(s) classé(s) (#{date})", warn

  -- Sortie en erreur si interruption par seuil d'erreurs (utile en CI/cron).
  os.exit 1 if run_state.aborted

main arg
