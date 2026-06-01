#!/usr/bin/env moon
-- tools/classifier/simplifier.moon
-- Outil autonome (Docker) de SIMPLIFICATION des listes de domaines.
--
-- Objet : remplacer des grappes de sous-domaines par leur domaine parent quand
-- c'est sûr. Exemple typique :
--   +sun1-13.userapi.com  +sun1-16.userapi.com  …  →  userapi.com
-- (custos autorise un domaine ET tous ses sous-domaines, cf. to_domainlist :
-- replier vers le parent est donc équivalent côté correspondance, mais bien plus
-- court.)
--
-- Tout n'est pas repliable : `userapi.com` est anodin, mais sur `google.com` on
-- peut vouloir autoriser `mail.google.com` tout en bloquant `www.google.com` et
-- `google.com` lui-même. La décision « replier ou non ce parent » est donc confiée
-- à une IA (même back-end qu'classifier : OpenRouter / API OpenAI-compatible).
--
-- Le cœur d'orchestration vit dans simplify.moon (partagé avec classifier) ; ce
-- fichier n'en est que l'enveloppe CLI (arguments, .bin, commit git).
--
-- Pipeline :
--   1. Découvre les catégories (<lists_dir>/*.txt) ; restreint à <list-name> si fourni.
--   2. Simplifie chaque catégorie (redondants gratuits + repli IA) — cf. simplify.moon.
--   3. Recompile les .bin custos (mêmes hashs xxh64 que src/filter/updater.moon).
--   4. Commit git automatique (pas de push).
--
-- Usage :
--   moon simplifier.moon [<list-name>] [options]
-- Options :
--   --lists-dir DIR     Répertoire des listes .txt        (défaut : lists)
--   --bin-dir DIR       Répertoire de sortie des .bin      (défaut : = lists-dir)
--   --model NAMES       Modèle(s) IA séparés par des virgules → round-robin
--   --min-children N    Seuil de sous-domaines pour proposer un parent (défaut 3)
--   --batch-size N      Parents candidats par requête IA   (défaut 30 ; 0 = tout)
--   --max-retries N     Tentatives max par lot             (défaut 3)
--   --samples N         Sous-domaines d'exemple par parent dans le prompt (défaut 5)
--   --dry-run           N'écrit rien : affiche seulement le plan de repli
--   --no-bin            Ne pas recompiler les .bin
--   --no-commit         Ne pas committer
--
-- Variables d'environnement : identiques à classifier (CLASSIFIER_API_URL,
-- CLASSIFIER_API_KEY/OPENROUTER_API_KEY, CLASSIFIER_MODEL, CLASSIFIER_ENV, CUSTOS_LUA).

-- ── Répertoires & package.path (AVANT tout require local) ─────────

script_dir = do
  src = arg and arg[0] or "tools/classifier/simplifier.moon"
  src\match("^(.*)/[^/]+$") or "."

package.path = "#{script_dir}/?.lua;#{package.path}"
-- Usage hors Docker (via `moon`, non précompilé) : permettre le chargement des
-- modules .moon voisins (common.moon, simplify_lib.moon, simplify.moon).
if package.moonpath
  package.moonpath = "#{script_dir}/?.moon;#{package.moonpath}"
custos_lua = os.getenv("CUSTOS_LUA") or "#{script_dir}/../../lua"
package.path = "#{custos_lua}/?.lua;#{custos_lua}/?/init.lua;#{package.path}"

common = require "common"
{ :load_dotenv, :env, :parse_models, :list_categories,
  :compile_bin, :git_commit } = common
simplify = require "simplify"
warn = common.make_warn "simplifier"

-- ── Configuration ─────────────────────────────────────────────────

load_dotenv os.getenv("CLASSIFIER_ENV") or ".env"

DEFAULT_MODELS = parse_models env("CLASSIFIER_MODEL")
DEFAULT_MODELS = { "openrouter/free" } if #DEFAULT_MODELS == 0

-- ── Analyse des arguments ─────────────────────────────────────────

parse_args = (argv) ->
  opts = {
    lists_dir:    "lists"
    bin_dir:      nil
    models:       DEFAULT_MODELS
    min_children: 3
    batch_size:   30
    max_retries:  3
    samples:      5
    dry_run:      false
    bin:          true
    commit:       true
    only:         nil
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
      when "--min-children"
        i += 1
        opts.min_children = tonumber(argv[i]) or 3
      when "--batch-size"
        i += 1
        opts.batch_size = tonumber(argv[i]) or 30
      when "--max-retries"
        i += 1
        opts.max_retries = tonumber(argv[i]) or 3
      when "--samples"
        i += 1
        opts.samples = tonumber(argv[i]) or 5
      when "--dry-run"
        opts.dry_run = true
      when "--no-bin"
        opts.bin = false
      when "--no-commit"
        opts.commit = false
      else
        opts.only = argv[i] unless argv[i]\sub(1, 2) == "--"
    i += 1
  opts.bin_dir or= opts.lists_dir
  opts

-- ── Point d'entrée ────────────────────────────────────────────────

main = (argv) ->
  opts = parse_args argv

  categories_set, categories = list_categories opts.lists_dir
  if #categories == 0
    warn "aucune catégorie trouvée dans #{opts.lists_dir} (fichiers *.txt attendus)"
    os.exit 1

  -- Restriction éventuelle à une seule catégorie.
  targets = categories
  if opts.only
    unless categories_set[opts.only]
      warn "catégorie inconnue : #{opts.only}"
      os.exit 1
    targets = { opts.only }

  warn "#{#targets} catégorie(s) à examiner"
  if #opts.models > 1
    warn "#{#opts.models} modèles en round-robin : #{table.concat opts.models, ', '}"
  else
    warn "modèle : #{opts.models[1]}"
  warn "DRY-RUN : aucune liste ne sera modifiée" if opts.dry_run

  ctx = {
    lists_dir:    opts.lists_dir
    models:       opts.models
    min_children: opts.min_children
    batch_size:   opts.batch_size
    max_retries:  opts.max_retries
    samples:      opts.samples
    dry_run:      opts.dry_run
    warn:         warn
    run_state:    { consecutive: 0, aborted: false, model_idx: 1 }
  }
  res = simplify.simplify_categories targets, ctx

  warn "total : #{res.parents} parent(s) replié(s), #{res.dropped} domaine(s) supprimé(s) (dont #{res.redundant} redondants)"

  if opts.bin and not opts.dry_run and #res.touched > 0
    written, errors = compile_bin opts.lists_dir, opts.bin_dir, res.touched, warn
    warn ".bin : #{written} écrit(s), #{errors} erreur(s)"

  if opts.commit and not opts.dry_run and #res.touched > 0
    date = os.date "%Y-%m-%d"
    git_commit opts.lists_dir, "simplifier: #{res.dropped} domaine(s) supprimé(s) — #{res.parents} repli(s) IA, #{res.redundant} redondants (#{date})", warn

  os.exit 1 if ctx.run_state.aborted

main arg
