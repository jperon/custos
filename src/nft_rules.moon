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
rule = require "filter.rule"

-- Expose rules_metadata for other modules to reuse without recompiling
rules_metadata = nil

-- ── Contexte nft (singleton) ─────────────────────────────────────────────────

ctx = libnft.nft_ctx_new 0
error "nft_rules: nft_ctx_new() failed" if ctx == nil
ffi.gc ctx, libnft.nft_ctx_free

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
      log_warn -> { action: "nft_cmd_failed", cmd: cmd, rc: rc, nft_err: nft_err or "" }
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

--- Collecte les adresses IP d'une interface via une commande shell.
-- @tparam string cmd   Commande shell (ex: "ip -4 addr show")
-- @tparam string pattern Pattern Lua pour extraire l'adresse
-- @tparam string|nil exclude Pattern d'exclusion (nil = pas d'exclusion)
-- @treturn table Liste des adresses IP extraites
collect_ips = (cmd, pattern, exclude) ->
  ips = {}
  fh = io.popen cmd
  if fh
    for line in fh\lines!
      ip = line\match pattern
      if ip and (not exclude or not ip\match exclude)
        ips[#ips + 1] = ip
    fh\close!
  ips

--- Formate une liste d'IPs en déclaration d'éléments nft inline.
-- @tparam table ips  Liste d'adresses IP
-- @treturn string    Ligne `    elements = { ip1, ip2 }\n` ou `""` si vide
fmt_elements = (ips) ->
  return "" if #ips == 0
  "    elements = { " .. table.concat(ips, ", ") .. " }\n"

substitute = (content, plan=nil) ->
  cfg = require "config"
  content = content\gsub "{QUEUE_QUESTIONS}", cfg.nfqueue.questions
  content = content\gsub "{QUEUE_RESPONSES}", cfg.nfqueue.responses
  content = content\gsub "{QUEUE_CAPTIVE}",   cfg.nfqueue.captive
  content = content\gsub "{QUEUE_REJECT}",    cfg.nfqueue.reject
  content = content\gsub "{QUEUE_AUTH}",      cfg.nfqueue.auth
  content = content\gsub "{QUEUE_SNI}",   cfg.nfqueue.sni
  content = content\gsub "{NFT_IP_TIMEOUT}",  cfg.nft.ip_timeout
  content = content\gsub "{DOH_PORT}",        tostring(cfg.doh.port or 8443)
  compiled_sets = if plan
    nft_compiler.render_sets_only cfg.filter, plan, "  ", true
  else
    "  # No compiled filter sets\n"
  content = content\gsub "{COMPILED_FILTER_SETS}", compiled_sets
  compiled_chains = if plan
    nft_compiler.render plan, "  ", true
  else
    "  chain cv_rules_dispatch {\n    return\n  }\n"
  content = content\gsub "{COMPILED_FILTER_RULES}", compiled_chains

  sip_rules = if cfg.nfqueue.sip
    q = cfg.nfqueue.sip
    table.concat {
      "    # SIP signalling + STUN → NFQUEUE (worker_sip)."
      "    # Toujours NF_ACCEPT ; apprend les IPs dans sip_peers + sets par règle."
      "    # dport 5060/5061 capture aussi les réponses opérateur à source port dynamique."
      "    # bypass : si le worker est absent, le trafic SIP passe quand même."
      "    meta l4proto {udp, tcp} th dport {5060, 5061} queue num #{q} bypass comment \"SIP outbound → NFQUEUE\""
      "    meta l4proto {udp, tcp} th sport {5060, 5061} queue num #{q} bypass comment \"SIP inbound → NFQUEUE\""
      "    meta l4proto udp        th dport 3478         queue num #{q} bypass comment \"STUN/ICE → NFQUEUE\""
      "    meta l4proto udp        th sport 3478         queue num #{q} bypass comment \"STUN/ICE responses → NFQUEUE\""
    }, "\n"
  else
    ""
  content = content\gsub "{SIP_RULES}", sip_rules

  -- Inspection SNI : placement piloté par sni.placement.
  --   "integral" → {SNI_RULES_PRE}  (avant cv_rules_dispatch) : tout le 443.
  --   "residual" → {SNI_RULES_POST} (après cv_action_vmap)    : filet de sécurité.
  -- {QUEUE_SNI} ayant déjà été substitué plus haut, on inline directement le n°.
  sni_q = cfg.nfqueue.sni
  sni_rules = table.concat {
    "    meta l4proto tcp th dport {443, 465, 587, 993, 995} tcp flags & (fin | syn | rst | ack) == ack log level debug prefix \"custos sni_tls: \" counter queue num #{sni_q} bypass comment \"TLS packets on TCP/443,465,587,993,995 (ACK, non-SYN) → SNI logger\""
    "    meta l4proto udp th dport 443 log level debug prefix \"custos sni_quic: \" counter queue num #{sni_q} bypass comment \"QUIC Initial UDP/443 → SNI logger\""
  }, "\n"
  placement = cfg.sni and cfg.sni.placement or "residual"
  pre_rules, post_rules = if placement == "integral"
    sni_rules, ""
  else
    "", sni_rules
  content = content\gsub "{SNI_RULES_PRE}",  pre_rules
  content = content\gsub "{SNI_RULES_POST}", post_rules

  -- Fast-path conntrack : deux ancres, une seule remplie selon le placement SNI.
  --   non-"integral" → ancre HAUTE ({FAST_PATH_EARLY}, avant le bloc infra) :
  --                    court-circuite tout le bloc amont pour les flux tranchés.
  --   "integral"     → ancre BASE ({FAST_PATH_LATE}, après {SNI_RULES_PRE}) :
  --                    préserve l'inspection SNI per-paquet du ClientHello.
  fast_path_rule = "    ct state established,related ct mark != 0x0 meta mark set ct mark counter meta mark vmap @cv_action_vmap comment \"Fast-path: replay cached verdict for decided flows\""
  early_fp, late_fp = if placement == "integral"
    "", fast_path_rule
  else
    fast_path_rule, ""
  content = content\gsub "{FAST_PATH_EARLY}", early_fp
  content = content\gsub "{FAST_PATH_LATE}",  late_fp

  -- Pré-peupler filter_ips4/6 dès l'application du ruleset pour éviter la
  -- race condition entre flush ruleset et nft_extra_rules.apply_from_config().
  ip4s = collect_ips "ip -4 addr show 2>/dev/null", "%s+inet%s+([%d%.]+)/", nil
  ip6s = collect_ips "ip -6 addr show 2>/dev/null", "%s+inet6%s+([%x:]+)/", "^fe80"

  content = content\gsub "{FILTER_IPS4_ELEMENTS}", fmt_elements ip4s
  content = content\gsub "{FILTER_IPS6_ELEMENTS}", fmt_elements ip6s

  if get_log_level_num"DEBUG" < get_log_level_num cfg.runtime.log_level
    content = content\gsub "log%s+level%s+debug%s+prefix%s+\"[^\"]*\"", ""

  content

-- Compile filter rules and return plan (without rendering into template)
-- @tparam table filter_cfg Filter configuration
-- @tparam table|nil rules_metadata Enriched metadata from rule.compile_rules()
-- @treturn table|nil Compiled plan
compile_filter_rules = (filter_cfg, rules_metadata=nil) ->
  return nil unless filter_cfg and filter_cfg.rules and #filter_cfg.rules > 0
  nft_compiler.compile filter_cfg, rules_metadata

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
    log_debug -> { action: "no_rule_sets_to_create" }
    return true
  
  log_info -> { action: "creating_per_rule_nft_sets", count: #commands }
  
  all_ok = true
  for _, cmd in ipairs commands
    ok, err = run_cmd cmd, { quiet: false }
    unless ok
      -- "already exists" is benign; log as debug only
      if err and err\find "already exists"
        log_debug -> { action: "set_already_exists", cmd: cmd }
      else
        log_warn -> { action: "set_creation_failed", cmd: cmd, err: err or "" }
        all_ok = false
  
  all_ok

-- ── Application Bridge ─────────────────────────────────────────────────────

--- Applique le ruleset bridge principal : template substitué + dynamic sets.
-- @treturn boolean true si succès
apply = ->
  path = nft_file_path!
  fh, err = io.open path, "r"
  unless fh
    log_warn -> { action: "nft_rules_file_missing", path: path, err: err }
    return false
  content = fh\read "*a"
  fh\close!

  cfg = require "config"
  -- Compile rules with enriched metadata for nft compilation
  compiled_rules = rule.compile_rules cfg.filter
  rules_metadata = compiled_rules.rules_metadata
  plan = compile_filter_rules cfg.filter, rules_metadata

  -- Log compilation metrics
  if plan and plan.metrics
    log_info -> {
      action: "nft_compile_metrics"
      total_rules: plan.metrics.total_rules
      nft_compilable: plan.metrics.nft_compilable
      worker_only: plan.metrics.worker_only
      conditions_compiled: plan.metrics.conditions_compiled
      conditions_worker_only: plan.metrics.conditions_worker_only
    }

  content = substitute content, plan

  -- Write template to temporary file and apply via nft -f
  tmpdir = "./tmp"
  -- Ensure tmp directory exists
  os.execute "mkdir -p #{tmpdir}"
  tmpfile = "#{tmpdir}/custos-rules-#{os.time!}.nft"
  tmpfh, tmp_err = io.open tmpfile, "w"
  unless tmpfh
    log_warn -> { action: "nft_rules_tempfile_failed", path: tmpfile, err: tmp_err }
    return false
  tmpfh\write content
  tmpfh\close!

  errfile = "#{tmpfile}.err"
  rc = os.execute "nft -f #{tmpfile} 2>#{errfile}"
  errtxt = ""
  errfh = io.open errfile, "r"
  if errfh
    errtxt = errfh\read("*a") or ""
    errfh\close!
  os.remove tmpfile
  os.remove errfile
  
  if rc != 0
    log_warn -> { action: "nft_rules_apply_failed", path: path, rc: rc, err: errtxt }
    return false

  log_info -> { action: "nft_rules_template_applied", path: path }

  -- Now create per-rule sets dynamically
  unless create_filter_rule_sets plan
    log_warn -> { action: "nft_rules_sets_creation_failed" }
    return false

  log_info -> { action: "nft_rules_applied", path: path }
  true

--- Libère le contexte nft (et son socket netlink NETLINK_NETFILTER).
-- Hygiène : à appeler après apply!, avant de forker les workers, pour ne pas
-- léguer inutilement ce fd à tous les enfants (le ruleset est déjà appliqué).
-- Sans effet sur la livraison NFQUEUE.
-- @treturn nil
close = ->
  if ctx
    ffi.gc ctx, nil          -- annule le finaliseur pour éviter un double free
    libnft.nft_ctx_free ctx
    ctx = nil

{ :apply, :close, _test: { :collect_ips, :fmt_elements, :substitute } }
