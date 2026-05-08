-- src/nft_rules.moon
-- Application des rulesets nftables principaux depuis Lua.
--
-- Lit les templates (.nft), substitue les placeholders
-- {QUEUE_*} et {NFT_IP_TIMEOUT} depuis config.moon, et applique
-- le ruleset via libnft (pas de fork, pas de `nft -f`).
--
-- Les valeurs de substitution sont lues depuis config à l'appel de apply(),
-- après le chargement éventuel de /var/run/custos/config.lua (UCI).
--
-- Interface :
--   nft_rules.apply()       — applique le ruleset bridge principal

{ :ffi, :libnft } = require "ffi_defs"
{ :log_info, :log_warn, :get_log_level_num } = require "log"

-- ── Contexte nft (singleton) ─────────────────────────────────────────────────

ctx = libnft.nft_ctx_new 0
error "nft_rules: nft_ctx_new() failed" if ctx == nil

-- ── Localisation des templates ─────────────────────────────────────────

--- Retourne le chemin du template dns-filter-bridge.nft.
-- Positionné dans le même répertoire que nft_rules.lua (via debug.getinfo).
-- @treturn string Chemin absolu du fichier template
nft_file_path = ->
  src = debug.getinfo(1, "S").source
  dir = src\match("^@(.*/)") or "./"
  dir .. "dns-filter-bridge.nft"

substitute = (content) ->
  cfg = require "config"
  content = content\gsub "{QUEUE_QUESTIONS}", cfg.QUEUE_QUESTIONS
  content = content\gsub "{QUEUE_RESPONSES}", cfg.QUEUE_RESPONSES
  content = content\gsub "{QUEUE_CAPTIVE}",   cfg.QUEUE_CAPTIVE
  content = content\gsub "{QUEUE_REJECT}",    cfg.QUEUE_REJECT
  content = content\gsub "{QUEUE_AUTH}",      cfg.QUEUE_AUTH
  content = content\gsub "{QUEUE_SNI_LOG}",   cfg.QUEUE_SNI_LOG
  content = content\gsub "{NFT_IP_TIMEOUT}",  cfg.NFT_IP_TIMEOUT

  if get_log_level_num"DEBUG" < get_log_level_num cfg.LOG_LEVEL
    content = content\gsub "log%s+level%s+debug%s+prefix%s+\"[^\"]*\"", ""

  content

-- ── Application Bridge ─────────────────────────────────────────────────────

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

  tmpfile = "/tmp/custos-rules.nft"
  tmpfh, tmp_err = io.open tmpfile, "w"
  unless tmpfh
    log_warn { action: "nft_rules_tempfile_failed", path: tmpfile, err: tmp_err }
    return false
  tmpfh\write content
  tmpfh\close!

  rc = os.execute "nft -f #{tmpfile} 2>/dev/null"
  if rc != 0
    log_warn { action: "nft_rules_apply_failed", path: path }
    return false

  log_info { action: "nft_rules_applied", path: path }
  true

{ :apply }
