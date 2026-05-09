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
nft_compiler = require "filter.nft_compiler"

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
  content = content\gsub "{QUEUE_QUESTIONS}", cfg.nfqueue.questions
  content = content\gsub "{QUEUE_RESPONSES}", cfg.nfqueue.responses
  content = content\gsub "{QUEUE_CAPTIVE}",   cfg.nfqueue.captive
  content = content\gsub "{QUEUE_REJECT}",    cfg.nfqueue.reject
  content = content\gsub "{QUEUE_AUTH}",      cfg.nfqueue.auth
  content = content\gsub "{QUEUE_SNI_LOG}",   cfg.nfqueue.sni_log
  content = content\gsub "{NFT_IP_TIMEOUT}",  cfg.nft.ip_timeout

  if get_log_level_num"DEBUG" < get_log_level_num cfg.runtime.log_level
    content = content\gsub "log%s+level%s+debug%s+prefix%s+\"[^\"]*\"", ""

  content

-- Compile filter rules into per-rule nft objects (sets, chains, maps)
compile_filter_rules = (filter_cfg) ->
  return "" unless filter_cfg and filter_cfg.rules and #filter_cfg.rules > 0
  plan = nft_compiler.compile filter_cfg
  nft_compiler.render plan

-- ── Application Bridge ─────────────────────────────────────────────────────

--- Applique le ruleset bridge principal : template substitué + règles compilées.
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

  -- Compile filter rules into per-rule nft objects and inject into template
  cfg = require "config"
  compiled_rules = compile_filter_rules cfg.filter
  if compiled_rules and #compiled_rules > 0
    -- Insert compiled rules before the closing brace of the table
    content = content\gsub "(table%s+bridge%s+[%w_%-]+%s*{.-)(%s*}%s*$)", "%1\n" .. compiled_rules .. "%2"

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
