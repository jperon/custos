-- tools/classifier/simplify.moon
-- Cœur d'orchestration de la simplification des listes (sans CLI, sans .bin, sans
-- commit). Partagé entre simplifier.moon (outil dédié) et classifier.moon (qui
-- simplifie les catégories enrichies avant de compiler les .bin).
--
-- Deux temps par catégorie :
--   1. Suppression « gratuite » des sous-domaines redondants (un ancêtre est déjà
--      présent dans la liste) — aucune décision IA, équivalence stricte.
--   2. Repli IA des grappes de sous-domaines vers leur parent quand c'est sûr.
--
-- L'appelant fournit un `ctx` :
--   lists_dir    répertoire des listes .txt
--   models       liste de modèles IA (round-robin)
--   min_children seuil de sous-domaines pour proposer un parent (défaut 3)
--   batch_size   parents candidats par requête IA (défaut 30 ; 0 = tout)
--   max_retries  tentatives max par lot (défaut 3)
--   samples      sous-domaines d'exemple par parent dans le prompt (défaut 5)
--   dry_run      n'écrit rien si vrai
--   warn         fonction de log (stderr)
--   run_state    { consecutive, aborted, model_idx } — créé si absent

common = require "common"
{ :call_ai, :rewrite_list, :MAX_CONSECUTIVE_ERRORS } = common
slib = require "simplify_lib"
parse_domains = require "filter.lib.parse_domains"

--- Lit les domaines d'un <lists_dir>/<cat>.txt (parser "simple" du projet).
read_list_domains = (lists_dir, cat) ->
  data = common.read_file "#{lists_dir}/#{cat}.txt"
  return {} unless data
  doms = parse_domains.parse "simple", data
  seen, out = {}, {}
  for d in *doms
    continue if seen[d]
    seen[d] = true
    out[#out + 1] = d
  out

--- Construit le prompt de jugement pour un lot de parents candidats.
build_prompt = (cat, cands, nsamples) ->
  lines = {
    "You are a network security expert curating a DNS allowlist for the category \"#{cat}\"."
    "In this system, allowing a domain ALSO allows every one of its subdomains (present and future)."
    "We want to shorten the list by replacing many specific subdomains with a single PARENT domain."
    ""
    "For each parent below, decide whether it is SAFE to collapse its subdomains into that single parent,"
    "i.e. to allow the ENTIRE parent domain and all of its subdomains."
    ""
    "Answer true when the parent is a dedicated, single-purpose domain where allowing all subdomains is"
    "harmless and expected (e.g. an API/CDN/asset host such as userapi.com or fbcdn.net)."
    "Answer false when the parent is a large or general-purpose provider, or a domain where one might"
    "legitimately want to allow some subdomains while blocking others (e.g. google.com, amazonaws.com),"
    "or a public suffix (e.g. co.uk, github.io, blogspot.com)."
    ""
    "Parents (with sample subdomains currently in the list):"
  }
  for c in *cands
    samples = [c.children[i] for i = 1, math.min(nsamples, #c.children)]
    extra = #c.children > nsamples and ", … (#{#c.children} total)" or ""
    lines[#lines + 1] = "- #{c.parent} (e.g. #{table.concat samples, ', '}#{extra})"
  lines[#lines + 1] = ""
  lines[#lines + 1] = "Reply ONLY with a JSON object mapping each parent to true or false, e.g."
  lines[#lines + 1] = "{\"userapi.com\": true, \"google.com\": false}. No prose, no explanation."
  table.concat lines, "\n"

--- Valide qu'une réponse IA couvre chaque parent attendu par un booléen.
validate_verdicts = (cands, verdicts) ->
  return false, "réponse non-objet" unless type(verdicts) == "table"
  for c in *cands
    v = verdicts[c.parent]
    return false, c.parent if v == nil or type(v) != "boolean"
  true

--- Soumet un lot de parents candidats à l'IA et renvoie les verdicts validés.
-- Round-robin de modèles + bascule sur 429 ; réponse mal formée rejetée et
-- relancée sur un autre provider. nil si abandon (seuil d'erreurs atteint).
judge_batch = (cat, cands, ctx) ->
  { :warn, :run_state } = ctx
  prompt = build_prompt cat, cands, ctx.samples or 5
  models = ctx.models
  nmodels = #models
  ignore = {}
  max = ctx.max_retries or 3
  attempt = 1
  idx = run_state.model_idx
  advance = -> idx = (idx % nmodels) + 1
  while attempt <= max
    model = models[idx]
    verdicts, provider, status = call_ai prompt, model, ignore
    unless verdicts
      run_state.consecutive += 1
      if status == 429 and nmodels > 1
        warn "modèle #{model} : 429 → bascule modèle suivant (#{run_state.consecutive}/#{MAX_CONSECUTIVE_ERRORS})"
        advance!
      else
        warn "modèle #{model} — tentative #{attempt}/#{max} échouée (#{run_state.consecutive}/#{MAX_CONSECUTIVE_ERRORS}) : #{provider}"
      if run_state.consecutive >= MAX_CONSECUTIVE_ERRORS
        run_state.aborted = true
        warn "ARRÊT : #{MAX_CONSECUTIVE_ERRORS} erreurs consécutives — simplification interrompue"
        return nil
      attempt += 1
      continue

    run_state.consecutive = 0
    ok, bad = validate_verdicts cands, verdicts
    unless ok
      warn "réponse incomplète/invalide de #{provider} (parent « #{bad} ») → on relance ailleurs (#{attempt}/#{max})"
      ignore[#ignore + 1] = provider if provider and provider != "?"
      advance!
      attempt += 1
      continue

    run_state.model_idx = (idx % nmodels) + 1
    return verdicts

  warn "abandon après #{max} tentative(s) : aucun verdict exploitable pour ce lot"
  nil

--- Juge TOUS les candidats d'une catégorie, par lots de ctx.batch_size.
-- @treturn table set { [parent]: true } des parents approuvés
judge_candidates = (cat, cands, ctx) ->
  { :warn, :run_state } = ctx
  approved = {}
  return approved if #cands == 0
  size = ctx.batch_size or 30
  size = #cands if size <= 0
  nbatches = math.ceil #cands / size
  for b = 1, nbatches
    break if run_state.aborted
    lo = (b - 1) * size + 1
    hi = math.min b * size, #cands
    batch = [cands[i] for i = lo, hi]
    warn "  lot #{b}/#{nbatches} : #{#batch} parent(s) candidat(s)" if nbatches > 1
    verdicts = judge_batch cat, batch, ctx
    break unless verdicts
    for c in *batch
      approved[c.parent] = true if verdicts[c.parent]
  approved

--- Simplifie une catégorie. Retourne :
--   napproved  nb de parents repliés via décision IA
--   ndrop      nb total de domaines supprimés (redondants + repliés)
--   nredundant nb de sous-domaines redondants supprimés sans IA
process_category = (cat, ctx) ->
  { :warn, :lists_dir } = ctx
  domains = read_list_domains lists_dir, cat
  return 0, 0, 0 if #domains == 0

  -- 1. Redondance « gratuite ».
  drop = slib.redundant domains
  nredundant = 0
  nredundant += 1 for _ in pairs drop
  warn "#{cat} : #{nredundant} sous-domaine(s) redondant(s) (parent déjà présent)" if nredundant > 0

  -- 2. Candidats au repli IA, sur les domaines NON redondants.
  remaining = [d for d in *domains when not drop[d]]
  cands = slib.candidates remaining, ctx.min_children
  warn "#{cat} : #{#cands} parent(s) candidat(s) sur #{#remaining} domaine(s)" if #cands > 0

  add, napproved = {}, 0
  if #cands > 0
    approved = judge_candidates cat, cands, ctx
    napproved += 1 for _ in pairs approved
    if napproved > 0
      fold_drop, fold_add = slib.fold_plan remaining, approved
      drop[d] = true for d in pairs fold_drop
      add = fold_add
      for p in *add
        warn "  ✓ repli → #{p}"
    else
      warn "  aucun repli approuvé"

  ndrop = 0
  ndrop += 1 for _ in pairs drop
  return 0, 0, 0 if ndrop == 0 and #add == 0

  if ctx.dry_run
    warn "  (dry-run) #{napproved} parent(s) replié(s), #{ndrop} domaine(s) supprimé(s) (dont #{nredundant} redondants)"
    return napproved, ndrop, nredundant

  rewrite_list "#{lists_dir}/#{cat}.txt", add, drop
  napproved, ndrop, nredundant

--- Simplifie une liste de catégories. Renvoie un récapitulatif :
--   { parents, dropped, redundant, touched } (touched = catégories modifiées).
-- S'arrête si ctx.run_state.aborted (seuil d'erreurs IA atteint).
simplify_categories = (categories, ctx) ->
  ctx.run_state or= { consecutive: 0, aborted: false, model_idx: 1 }
  out = { parents: 0, dropped: 0, redundant: 0, touched: {} }
  for cat in *categories
    break if ctx.run_state.aborted
    np, nd, nr = process_category cat, ctx
    if nd > 0
      out.parents += np
      out.dropped += nd
      out.redundant += nr
      out.touched[#out.touched + 1] = cat unless ctx.dry_run
  out

{ :read_list_domains, :build_prompt, :validate_verdicts, :judge_batch,
  :judge_candidates, :process_category, :simplify_categories }
