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
-- Architecture :
--   - Template contains only framework sets (mac*_allowed, ip*_allowed, etc)
--   - Per-rule sets are created dynamically via "nft add set" commands
--   - This separation allows rules to be added/removed without full recompile
--
-- Interface :
--   nft_rules.apply()       — applique le ruleset bridge principal

{ :ffi, :libnft } = require "ffi_defs"
{ :log_info, :log_warn, :log_debug, :get_log_level_num } = require "log"
nft_compiler = require "filter.nft_compiler"
nft_dynamic_sets = require "filter.nft_dynamic_sets"

-- ── Contexte nft (singleton) ─────────────────────────────────────────────────

ctx = libnft.nft_ctx_new 0
error "nft_rules: nft_ctx_new() failed" if ctx == nil

-- ── Interface with libnft ──────────────────────────────────────────────

--- Retourne le code erreur du contexte nft.
get_error_buffer = ->
  return nil unless ctx
  ok, ptr = pcall -> libnft.nft_ctx_get_error_buffer ctx
  return nil unless ok and ptr != nil
  msg = ffi.string ptr
  msg if msg and msg != ""

--- Execute nft command via libnft context.
run_cmd = (cmd, opts=nil) ->
  rc = libnft.nft_run_cmd_from_buffer ctx, cmd
  if rc != 0
    nft_err = get_error_buffer!
    unless opts and opts.quiet
      log_warn { action: "nft_cmd_failed", cmd: cmd, rc: rc, nft_err: nft_err or "" }
    return false, nft_err
  true, nil

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

  sip_rules = if cfg.nfqueue.sip
    q = cfg.nfqueue.sip
    table.concat {
      "    # SIP signalling + STUN → NFQUEUE (worker_sip)."
      "    # Toujours NF_ACCEPT ; insère les IPs media dans mac4/mac6_allowed."
      "    # bypass : si le worker est absent, le trafic SIP passe quand même."
      "    meta l4proto {udp, tcp} th dport {5060, 5061} queue num #{q} bypass comment \"SIP outbound → NFQUEUE\""
      "    meta l4proto {udp, tcp} th sport {5060, 5061} queue num #{q} bypass comment \"SIP inbound → NFQUEUE\""
      "    meta l4proto udp        th dport 3478         queue num #{q} bypass comment \"STUN/ICE → NFQUEUE\""
      "    meta l4proto udp        th sport 3478         queue num #{q} bypass comment \"STUN/ICE responses → NFQUEUE\""
    }, "\n"
  else
    ""
  content = content\gsub "{SIP_RULES}", sip_rules

  if get_log_level_num"DEBUG" < get_log_level_num cfg.runtime.log_level
    content = content\gsub "log%s+level%s+debug%s+prefix%s+\"[^\"]*\"", ""

  content

-- Compile filter rules and return plan (without rendering into template)
compile_filter_rules = (filter_cfg) ->
  return nil unless filter_cfg and filter_cfg.rules and #filter_cfg.rules > 0
  nft_compiler.compile filter_cfg

-- ── Dynamic Set Creation ─────────────────────────────────────────────────────

--- Execute all per-rule set creation commands.
-- Creates sets via "nft add set" instead of embedding in template.
-- Gracefully handles "already exists" errors.
-- @tparam table plan compiled filter plan
-- @treturn boolean true if all sets created successfully
create_filter_rule_sets = (plan) ->
  return true unless plan and plan.rules and #plan.rules > 0
  
  commands = nft_dynamic_sets.generate_set_creation_commands plan
  
  if #commands == 0
    log_debug { action: "no_rule_sets_to_create" }
    return true
  
  log_info { action: "creating_per_rule_nft_sets", count: #commands }
  
  all_ok = true
  for _, cmd in ipairs commands
    ok, err = run_cmd cmd, { quiet: false }
    unless ok
      -- "already exists" is benign; log as debug only
      if err and err\find "already exists"
        log_debug { action: "set_already_exists", cmd: cmd }
      else
        log_warn { action: "set_creation_failed", cmd: cmd, err: err or "" }
        all_ok = false
  
  all_ok

-- ── Application Bridge ─────────────────────────────────────────────────────

--- Applique le ruleset bridge principal : template substitué + dynamic sets.
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

  -- Write template to temporary file and apply via nft -f
  tmpdir = "./tmp"
  -- Ensure tmp directory exists
  os.execute "mkdir -p #{tmpdir}"
  tmpfile = "#{tmpdir}/custos-rules-#{os.time!}.nft"
  tmpfh, tmp_err = io.open tmpfile, "w"
  unless tmpfh
    log_warn { action: "nft_rules_tempfile_failed", path: tmpfile, err: tmp_err }
    return false
  tmpfh\write content
  tmpfh\close!

  rc = os.execute "nft -f #{tmpfile} 2>/dev/null"
  os.remove tmpfile
  
  if rc != 0
    log_warn { action: "nft_rules_apply_failed", path: path }
    return false

  log_info { action: "nft_rules_template_applied", path: path }

  -- Now create per-rule sets dynamically
  cfg = require "config"
  plan = compile_filter_rules cfg.filter
  unless create_filter_rule_sets plan
    log_warn { action: "nft_rules_sets_creation_failed" }
    return false

  log_info { action: "nft_rules_applied", path: path }
  true

{ :apply }

