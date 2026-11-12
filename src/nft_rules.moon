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
{ :REJECT_MARK_HEX } = require "nft_marks"
{ :exec_ok } = require "lib.os_exec"

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

-- ── Règles DNS (questions / réponses) ─────────────────────────────────────────
--
-- Sélecteurs, préfixe de log, compteur et commentaire : identiques à ceux de la
-- règle littérale du template. Ce qui change, quand une plage contient PLUS
-- D'UNE file, c'est la répartition des paquets :
--
--   - une file : `queue num X`, à l'identique (comportement historique) ;
--   - plusieurs files : `queue to jhash <clé> mod N offset <première file>`,
--     une règle par famille (IPv4/IPv6). La clé porte sur l'IP ET le port du
--     CLIENT (questions : source, réponses : destination), alors que
--     `queue num A-B` fait hacher au noyau le couple d'adresses symétrique
--     SANS les ports (nfqueue_hash, docs/agents/perf.md §11.1) : avec le
--     second avis, toutes les réponses du validateur partaient donc sur UNE
--     file de la plage (70,6 % du trafic, §15.2/§16.3).
--
-- Choix de syntaxe (validés par probe local nft 1.1.6, cf.
-- docs/agents/perf.md §11.5 et tmp/qhash_report.md) :
--   * sélecteur de famille `ip version 4` / `ip6 version 6` : il est
--     INDISPENSABLE (sans lui, `ip saddr` sur un paquet IPv6 lit 4 octets
--     pertinents en apparence au milieu d'un en-tête de 40 octets et fausse la
--     répartition), et il est retenu car il matche aussi les trames VLAN
--     encapsulées (ethertype 0x8100), contrairement à `ether type ip/ip6` qui
--     ne voit que l'ethertype externe. `meta nfproto` est refusé par nft dans
--     la famille bridge.
--   * `th sport` / `th dport` sont acceptés dans l'expression jhash (et non
--     seulement `udp`/`tcp`), ce qui évite de doubler les règles par proto.
--   * pas de `bypass` : la règle historique n'en a pas ; un paquet sans
--     listener doit rester droppé, sinon il contournerait le filtre DNS.
DNS_RULES = {
  questions: {
    selector: "meta l4proto {udp, tcp} th dport 53"
    log_prefix: "custos question: "
    comment: "DNS questions → NFQUEUE"
    v4: { "ip version 4",  "ip saddr . th sport" }
    v6: { "ip6 version 6", "ip6 saddr . th sport" }
  }
  responses: {
    selector: "meta l4proto {udp, tcp} th sport 53"
    log_prefix: "custos response: "
    comment: "DNS responses → NFQUEUE"
    v4: { "ip version 4",  "ip daddr . th dport" }
    v6: { "ip6 version 6", "ip6 daddr . th dport" }
  }
}

--- Découpe une liste de numéros de file en segments contigus.
-- "0,2" → {{0},{2}} ; "0-1,4-5" → {{0,1},{4,5}} ; "14-15" → {{14,15}}.
-- @tparam table queues Numéros retournés par lib.lowmem.parse_queues
-- @treturn table Liste de segments (tableaux d'entiers contigus croissants)
contiguous_segments = (queues) ->
  segments = {}
  current = nil
  for q in *queues
    if current and q == current[#current] + 1
      current[#current + 1] = q
    else
      current = { q }
      segments[#segments + 1] = current
  segments

--- Construit le bloc de règles DNS pour la plage configurée.
--
-- Une seule file  → la règle historique `queue num X`.
-- Plusieurs files → une règle par famille (IPv4 puis IPv6) avec
--   `queue to jhash <clé> mod N offset <première file>` (N = taille du
--   segment, offset = sa première file : les files couvertes sont donc
--   exactement celles de la plage).
-- Liste discontinue ("0,2") → une règle par segment : un `queue num` par file
-- isolée, car `mod N offset premier` ne couvrirait que [premier, premier+N-1]
-- et priverait les autres files de leurs paquets (elles n'auraient aucun
-- listener).
-- @tparam string|nil spec    Valeur de nfqueue.questions / nfqueue.responses
-- @tparam string direction   "questions" ou "responses"
-- @treturn string Bloc indenté de 4 espaces, lignes séparées par "\n"
dns_queue_rules = (spec, direction) ->
  s = DNS_RULES[direction]
  error "nft_rules: direction DNS inconnue: #{tostring direction}" unless s
  log_stmt = "log level debug prefix \"#{s.log_prefix}\" counter"
  tail = "comment \"#{s.comment}\""
  lowmem = require "lib.lowmem"
  queues = lowmem.parse_queues spec
  lines = {}
  if #queues == 0
    -- Valeur illisible : on recopie la valeur brute (comportement historique ;
    -- nft signalera une éventuelle invalidité au moment d'appliquer le ruleset).
    lines[#lines + 1] = "#{s.selector} #{log_stmt} queue num #{tostring spec} #{tail}"
  else
    for segment in *contiguous_segments queues
      if #segment == 1
        lines[#lines + 1] = "#{s.selector} #{log_stmt} queue num #{segment[1]} #{tail}"
      else
        for pair in *{ s.v4, s.v6 }
          fam, key = pair[1], pair[2]
          lines[#lines + 1] = "#{s.selector} #{fam} #{log_stmt} queue to jhash #{key} mod #{#segment} offset #{segment[1]} #{tail}"
  out = {}
  for line in *lines
    out[#out + 1] = "    #{line}"
  table.concat out, "\n"

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

  -- Règles DNS (ancres du template) : `queue num X` pour une seule file,
  -- jhash (IP, port) du client par famille pour une plage. Voir dns_queue_rules.
  dns_questions = dns_queue_rules cfg.nfqueue.questions, "questions"
  dns_responses = dns_queue_rules cfg.nfqueue.responses, "responses"
  content = content\gsub "{DNS_QUESTIONS_RULES}", dns_questions
  content = content\gsub "{DNS_RESPONSES_RULES}", dns_responses

  -- Chaîne input bridge de détection VLAN pour les clients DoH.
  -- Rendue uniquement si DoH est activé ET qu'une file doh_vlan est configurée.
  -- Voir worker_doh_vlan + AGENTS.md « from_vlan en DoH ».
  doh_vlan_chain = if cfg.doh and cfg.doh.enabled and cfg.nfqueue.doh_vlan
    doh_port = tostring(cfg.doh.port or 8443)
    q = cfg.nfqueue.doh_vlan
    table.concat {
      "  # ── Chaîne INPUT bridge : détection VLAN pour les clients DoH ──"
      "  # Recopie le tag 802.1Q dans le mark (lisible via nfq_get_nfmark) puis"
      "  # queue vers worker_doh_vlan, qui apprend IP→VLAN (NF_ACCEPT toujours)."
      "  chain input {"
      "    type filter hook input priority 0; policy accept;"
      "    meta pkttype host vlan id != 0 meta l4proto tcp tcp dport #{doh_port} meta mark set vlan id counter queue num #{q} bypass comment \"DoH VLAN detection (tagged)\""
      "    meta pkttype host meta l4proto tcp tcp dport #{doh_port} counter queue num #{q} bypass comment \"DoH VLAN detection (untagged)\""
      "  }"
    }, "\n"
  else
    "  # DoH VLAN detection disabled (DoH off or nfqueue.doh_vlan unset)"
  content = content\gsub "{DOH_VLAN_INPUT_CHAIN}", doh_vlan_chain

  -- Règles d'apprentissage VLAN DoH dans le hook forward (tag présent avant
  -- routage). Voir worker_doh_vlan + AGENTS.md « from_vlan en DoH ».
  doh_vlan_forward = if cfg.doh and cfg.doh.enabled and cfg.nfqueue.doh_vlan
    doh_port = tostring(cfg.doh.port or 8443)
    q = cfg.nfqueue.doh_vlan
    table.concat {
      "    vlan id != 0 tcp dport #{doh_port} ip  daddr @filter_ips4 meta mark set vlan id counter queue num #{q} bypass comment \"DoH VLAN learn (forward tagged v4)\""
      "    vlan id != 0 tcp dport #{doh_port} ip6 daddr @filter_ips6 meta mark set vlan id counter queue num #{q} bypass comment \"DoH VLAN learn (forward tagged v6)\""
    }, "\n"
  else
    "    # DoH VLAN forward-learning disabled (DoH off or nfqueue.doh_vlan unset)"
  content = content\gsub "{DOH_VLAN_FORWARD_RULES}", doh_vlan_forward
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
  reject_q = cfg.nfqueue.reject
  sni_rules = table.concat {
    "    meta l4proto tcp th dport 443 tcp flags & (fin | syn | rst | ack) == ack log level debug prefix \"custos sni_tls: \" counter queue num #{sni_q} bypass comment \"TLS packets on TCP/443 (ACK, non-SYN) → SNI logger\""
    "    meta l4proto udp th dport 443 log level debug prefix \"custos sni_quic: \" counter queue num #{sni_q} bypass comment \"QUIC Initial UDP/443 → SNI logger\""
    "    meta mark #{REJECT_MARK_HEX} counter queue num #{reject_q} comment \"SNI refused packet → worker_reject\""
    "    meta mark #{REJECT_MARK_HEX} meta mark set 0x0 accept comment \"Clear SNI reject mark after forged reject\""
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

  -- Write template to temporary file and apply via nft -f.
  -- Chemin absolu tmpfs : le service tourne avec cwd=/, où "./tmp" ne tombe
  -- dans /tmp que par accident (et pas sur un tmpfs monté ailleurs).
  tmpdir = "/tmp/custos"
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

  unless exec_ok rc
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

{ :apply, :close, _test: { :collect_ips, :fmt_elements, :substitute, :dns_queue_rules } }
