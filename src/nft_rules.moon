-- src/nft_rules.moon
-- Application du ruleset nftables principal depuis Lua.
--
-- Lit le template dns-filter-bridge.nft, substitue les placeholders
-- {QUEUE_*} et {NFT_IP_TIMEOUT} depuis config.moon, et applique le
-- ruleset via libnft (pas de fork, pas de `nft -f`).
--
-- Les valeurs de substitution sont lues depuis config à l'appel de apply(),
-- après le chargement éventuel de /var/run/custos/config.lua (UCI).
--
-- Interface :
--   nft_rules.apply()  — applique le ruleset complet substitué

{ :ffi, :libnft } = require "ffi_defs"
{ :log_info, :log_warn } = require "log"

-- ── Contexte nft (singleton) ─────────────────────────────────────────────────

ctx = libnft.nft_ctx_new 0
error "nft_rules: nft_ctx_new() failed" if ctx == nil

-- ── Localisation du template ─────────────────────────────────────────────────

--- Retourne le chemin du template dns-filter-bridge.nft.
-- Positionné dans le même répertoire que nft_rules.lua (via debug.getinfo).
-- @treturn string Chemin absolu du fichier template
nft_file_path = ->
  src = debug.getinfo(1, "S").source
  dir = src\match("^@(.*/)") or "./"
  dir .. "dns-filter-bridge.nft"

-- ── Substitution des placeholders ────────────────────────────────────────────

--- Substitue les placeholders {QUEUE_*} et {NFT_IP_TIMEOUT} par les valeurs
-- de config.moon dans le contenu du template .nft.
-- Config est chargé à la demande pour prendre en compte les overrides UCI.
-- @tparam string content Contenu brut du template
-- @treturn string Contenu avec les valeurs substituées
substitute = (content) ->
  cfg = require "config"
  content = content\gsub "{QUEUE_QUESTIONS}", cfg.QUEUE_QUESTIONS
  content = content\gsub "{QUEUE_RESPONSES}", cfg.QUEUE_RESPONSES
  content = content\gsub "{QUEUE_CAPTIVE}",   cfg.QUEUE_CAPTIVE
  content = content\gsub "{QUEUE_REJECT}",    cfg.QUEUE_REJECT
  content = content\gsub "{NFT_IP_TIMEOUT}",  cfg.NFT_IP_TIMEOUT
  content

-- ── Application ──────────────────────────────────────────────────────────────

--- Lit le template dns-filter-bridge.nft, substitue les placeholders
-- depuis config.moon et applique le ruleset via libnft.
-- @treturn boolean true si succès
apply = ->
  path = nft_file_path!
  fh, err = io.open path, "r"
  unless fh
    log_warn { action: "nft_rules_file_missing", path: path, err: err }
    return false
  content = fh\read "*a"
  fh\close!

  content = substitute content

  rc = libnft.nft_run_cmd_from_buffer ctx, content
  if rc != 0
    log_warn { action: "nft_rules_apply_failed", path: path, rc: rc }
    return false

  log_info { action: "nft_rules_applied", path: path }
  true

{ :apply }
