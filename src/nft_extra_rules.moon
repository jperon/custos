-- src/nft_extra_rules.moon
-- Module d'application de règles nft supplémentaires fournies via UCI.
--
-- Les règles UCI sont des fragments de règles nftables (sans préfixe
-- "insert rule <table> <chain> ..."). Elles seront insérées en tête
-- de la chaîne `forward` de la table configurée (position 0).
--
-- Exemple d'entrée UCI (custos.main.nft_extra_rules):
--   ip saddr 10.0.0.0/8 counter log prefix "extra: " accept
--
-- Comportement :
--   - Au démarrage, le module supprime d'abord d'éventuelles occurrences
--     résiduelles d'un fragment donné, puis insère une unique occurrence.
--     Cela évite les insertions dupliquées si le service a redémarré sans
--     nettoyage préalable.
--   - À l'arrêt, le module tente de supprimer toutes les occurrences du
--     fragment (boucle delete until fail) ; suppression best-effort.
--
-- NOTE: Le module utilise libnft via FFI. Les erreurs rc != 0 sont loggées.

{ :ffi, :libnft } = require "ffi_defs"
{ :NFT_FAMILY, :NFT_TABLE } = require "config"
{ :log_warn, :log_info } = require "log"

-- Contexte nft
ctx = libnft.nft_ctx_new 0
error "nft_ctx_new() échoué dans nft_extra_rules" if ctx == nil

-- Liste des règles insérées par ce module (chaînes exactes telles qu'insérées).
inserted_rules = {}

--- Exécute une commande nft via le contexte FFI.
-- Journalise un warning en cas d'échec.
-- @tparam string cmd Commande nft complète (ex: "insert rule <family> <table> ...")
-- @treturn boolean true si succès (rc == 0)
run_cmd = (cmd) ->
  rc = libnft.nft_run_cmd_from_buffer ctx, cmd
  if rc != 0
    ts = os.time!
    log_warn { action: "nft_extra_cmd_failed", cmd: cmd, rc: rc, ts: ts }
    return false, rc
  true, 0

--- Insère une liste de règles en tête de la chaîne `forward`.
-- Avant insertion, recherche les occurrences existantes via `nft -a list chain`
-- et supprime par `handle` (plus robuste que suppression par expression).
-- Puis insère une unique occurrence en position 0 pour éviter les duplications
-- laissées par des redémarrages antérieurs.
-- @tparam table rules Liste de chaînes (fragments de règles nft)
-- @treturn boolean true si toutes les insertions ont réussi (au moins une tentative)
find_handles_for_fragment = (fragment) ->
  -- Retourne une table de handles (numbers) pour les lignes contenant fragment
  handles = {}
  -- Utilise le binaire nft en lecture pour obtenir la sortie annotée (-a)
  cmd = "nft -a list chain #{NFT_FAMILY} #{NFT_TABLE} forward 2>/dev/null"
  fh = io.popen cmd
  return handles unless fh
  out = fh\read "*a"
  fh\close!
  if out and #out > 0
    for line in out\gmatch "[^\n]+"
      -- recherche littérale du fragment (match exact substr) ; tolère espaces/format
      if line\find fragment, 1, true
        h = line\match "handle%s+(%d+)"
        if h
          table.insert handles, tonumber h
  handles

init = (rules) ->
  inserted_rules = {}
  return true unless rules and #rules > 0

  all_ok = true
  -- Parcours inverse pour que l'ordre UCI soit respecté en tête de chaîne.
  for i = #rules, 1, -1
    r = tostring rules[i]\gsub "%s+", " "  -- collapse whitespace
    r = r\match "^%s*(.-)%s*$"             -- trim
    continue if #r == 0

    -- Repérer et supprimer les occurrences existantes via leurs handles.
    handles = find_handles_for_fragment r
    if handles and #handles > 0
      for h in *handles
        del_cmd = "delete rule #{NFT_FAMILY} #{NFT_TABLE} forward handle #{h}"
        removed, rc = run_cmd del_cmd
        if removed
          log_info { action: "nft_extra_rule_removed_existing", rule: r, handle: h }
        else
          log_warn { action: "nft_extra_rule_remove_failed", rule: r, handle: h, rc: rc }

    -- Insérer une unique occurrence en position 0
    insert_cmd = "insert rule #{NFT_FAMILY} #{NFT_TABLE} forward position 0 #{r}"
    ok, rc = run_cmd insert_cmd
    if ok
      -- Conserver la représentation exacte pour tentative de suppression ultérieure.
      table.insert inserted_rules, r
      log_info { action: "nft_extra_rule_added", rule: r }
    else
      all_ok = false
      log_warn { action: "nft_extra_rule_add_failed", rule: r, rc: rc }
  all_ok

--- Applique les règles définies dans la config exportée (config.NFT_EXTRA_RULES).
-- Si la chaîne `forward` est absente (ex : respawn procd sans appel de
-- start_service), le fichier nft principal est ré-appliqué automatiquement
-- pour recréer la table avant d'insérer les règles UCI.
-- @treturn boolean true si toutes les insertions ont réussi
apply_from_config = ->
  -- Vérifier si la chaîne forward existe. Si non (cas typique : respawn procd
  -- après un stop/start non coordonné), ré-appliquer le ruleset principal.
  rc_check = os.execute "nft list chain #{NFT_FAMILY} #{NFT_TABLE} forward >/dev/null 2>&1"
  if rc_check ~= 0
    ok, rc = require("nft_rules").apply!
    unless ok
      log_warn { action: "nft_extra_main_rules_reapply_failed", rc: rc or -1 }
      return false
    log_info { action: "nft_extra_main_rules_reapplied" }
  cfg = require "config"
  rules = cfg.NFT_EXTRA_RULES or {}
  init rules

--- Supprime les règles précédemment insérées par ce module.
-- Tente `delete rule <family> <table> forward <expr>` pour chaque règle
-- stockée dans `inserted_rules`. Les suppressions sont best-effort.
-- @treturn nil
cleanup = ->
  -- On tente de supprimer toutes les occurrences connues ou présentes pour
  -- chaque fragment UCI. On combine les règles déjà insérées et les règles
  -- encore présentes dans la config pour nettoyer les résidus éventuels.
  rules_to_clean = {}
  if inserted_rules and #inserted_rules > 0
    for r in *inserted_rules
      table.insert rules_to_clean, r

  -- Ajouter aussi les fragments depuis la config (au cas où inserted_rules est vide)
  ok, cfg = pcall -> require "config"
  if ok and cfg and cfg.NFT_EXTRA_RULES
    for r in *cfg.NFT_EXTRA_RULES
      if r and #tostring(r) > 0
        table.insert rules_to_clean, tostring r

  -- Dédupliquer sommairement (map)
  seen = {}
  uniq = {}
  for r in *rules_to_clean
    if not seen[r]
      seen[r] = true
      table.insert uniq, r
  rules_to_clean = uniq

  if #rules_to_clean > 0
    for r in *rules_to_clean
      r = tostring r\gsub "%s+", " "
      r = r\match "^%s*(.-)%s*$"
      continue if #r == 0

      handles = find_handles_for_fragment r
      if handles and #handles > 0
        for h in *handles
          cmd = "delete rule #{NFT_FAMILY} #{NFT_TABLE} forward handle #{h}"
          ok, rc = run_cmd cmd
          if ok
            log_info { action: "nft_extra_rule_removed_on_cleanup", rule: r, handle: h }
          else
            log_warn { action: "nft_extra_rule_delete_failed", rule: r, handle: h, rc: rc }

    inserted_rules = {}

  libnft.nft_ctx_free ctx if ctx != nil

{ :init, :cleanup, :apply_from_config, :run_cmd }
