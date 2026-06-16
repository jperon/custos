-- src/worker_tls.moon
-- Worker NFQUEUE pour l'enregistrement des SNI depuis TLS/QUIC.
-- Capture les paquets TCP/443 avec payload TLS (ClientHello) et UDP/443 (QUIC Initial),
-- extrait les SNI via ipparse, et enregistre les métadonnées enrichies (MAC, IPs, ports, protocole).

{ :ffi, :libc, :libnfq } = require "ffi_defs"
{ :run_queue, :NF_ACCEPT, :NF_DROP } = require "nfq_loop"
{ :get_l2 } = require "nfq/ethernet"
{ :log_allow, :log_block, :log_info, :log_warn, :log_error, :log_debug, :set_action_prefix } = require "log"
{ :user_for_mac } = require "auth.sessions"

-- ipparse modules for packet parsing and SNI extraction
ipparse_ip = require "ipparse.l3.ip"
ipparse_tcp = require "ipparse.l4.tcp"
ipparse_udp = require "ipparse.l4.udp"
ipparse_quic = require "ipparse.l4.quic"
ipparse_quic_session = require "ipparse.l7.quic.session"
ipparse_tls = require "ipparse.l7.tls"
ipparse_tls_handshake = require "ipparse.l7.tls.handshake"
ipparse_tls_client_hello = require "ipparse.l7.tls.handshake.client_hello"
ipparse_server_name = require "ipparse.l7.tls.handshake.extension.server_name"
ipparse_supported_versions = require "ipparse.l7.tls.handshake.extension.supported_versions"
{ new: new_tcp_stream } = require "ipparse.l4.tcp_stream"
{ :mac2s } = require "packet_utils"

bit = require "bit"
{ :nft } = require "config"
nft_cfg = nft or {}
SNI_TIMEOUT = nft_cfg.sni_timeout or nft_cfg.ip_timeout or "2m"

-- État de réassemblage QUIC, indexé par flow key. `quic_sessions_seen`
-- mémorise la dernière activité (os.time) pour permettre une éviction TTL ;
-- sans cela, un flux QUIC qui n'aboutit jamais (ni SNI ni push_failed) resterait
-- indéfiniment en mémoire — fuite réelle sur routeur à faible RAM.
quic_sessions = {}
quic_sessions_seen = {}
quic_sessions_count = 0
QUIC_SESSION_TTL = 30      -- secondes sans activité avant éviction
QUIC_SESSION_MAX = 4096    -- plafond dur ; déclenche un balayage si dépassé

-- Réassemblage des ClientHello TLS fragmentés sur plusieurs segments TCP.
-- Un ClientHello tient en un seul enregistrement TLS Handshake (type 0x16) mais
-- peut être segmenté par TCP (petit MTU, PMTUd cassé, ClientHello volumineux).
-- Le prédicat ci-dessous bufferise jusqu'au record complet ; pour un premier
-- segment non-Handshake il renvoie aussitôt `true`, donc le trafic 443 non-TLS
-- (connexions déjà établies) n'est jamais bufferisé.
tls_record_complete = (buf) ->
  return true if buf\byte(1) != 0x16
  return false if #buf < 5
  rec_len = buf\byte(4) * 256 + buf\byte(5)
  #buf >= 5 + rec_len
tcp_state = new_tcp_stream tls_record_complete
TCP_PURGE_EVERY = 512      -- balaye les flux dormants tous les N paquets TCP
tcp_pkt_count = 0

filter = nil
sni_policy = nil
cmd_for = nil
run_cmd = nil
events_wfd = nil

-- Config et modules pour le second avis (validateur DNS) appliqué au SNI.
-- Chargés paresseusement (comme nft) : un worker SNI sans règle `validate` ne
-- paie jamais l'import du client DoH/UDP.
second_opinion_cfg = nil
validator_mod = nil
cname_mod = nil
filter_cfg = nil

-- Cache de verdict du validateur, indexé par domaine. Impératif perf : avec le
-- fast-path ct-mark, seul le PREMIER paquet de chaque flux monte en userspace ;
-- sans cache, chaque nouveau flux vers un domaine sous `validate` referait un
-- aller-retour upstream synchrone. Éviction paresseuse + plafond dur (même
-- approche que quic_sessions).
sni_verdict_cache = {}
sni_verdict_count = 0
SNI_VERDICT_TTL = 60       -- secondes (surchargé par second_opinion.verdict_ttl_s)
SNI_VERDICT_MAX = 4096     -- plafond dur

-- Supprime les sessions QUIC inactives depuis plus de QUIC_SESSION_TTL.
-- @tparam[opt] number now Horodatage courant (injectable pour les tests).
-- @treturn number Nombre de sessions évincées.
prune_quic_sessions = (now=os.time!) ->
  removed = 0
  for key, seen in pairs quic_sessions_seen
    if now - seen >= QUIC_SESSION_TTL
      quic_sessions[key] = nil
      quic_sessions_seen[key] = nil
      removed += 1
  quic_sessions_count -= removed
  removed

-- Réinitialise complètement l'état QUIC (utile pour les tests).
-- Vide les tables en place (sans réassigner) pour préserver les références.
reset_quic_sessions = ->
  for k in pairs quic_sessions
    quic_sessions[k] = nil
  for k in pairs quic_sessions_seen
    quic_sessions_seen[k] = nil
  quic_sessions_count = 0

-- Insère une session factice (test seam) et renvoie le compteur courant.
-- @tparam string key Flow key
-- @tparam[opt] number seen Horodatage de dernière activité
seed_quic_session = (key, seen=os.time!) ->
  unless quic_sessions[key]
    quic_sessions[key] = { stub: true }
    quic_sessions_count += 1
  quic_sessions_seen[key] = seen
  quic_sessions_count

-- Nombre de sessions QUIC actuellement suivies (test seam).
quic_session_count = -> quic_sessions_count

-- Réinitialise l'état de réassemblage TCP (test seam).
reset_tcp_sessions = ->
  tcp_state.reset!
  tcp_pkt_count = 0

-- Pousse un segment TCP dans le défragmenteur et renvoie le ClientHello complet
-- (ou nil tant qu'il manque des octets / sur segment de contrôle). Inclut la
-- purge périodique des flux dormants pour borner la mémoire.
-- @treturn string|nil Enregistrement TLS Handshake complet, ou nil.
feed_tls_segment = (key, segment, flags, seq) ->
  tcp_pkt_count += 1
  if tcp_pkt_count >= TCP_PURGE_EVERY
    tcp_state.purge!
    tcp_pkt_count = 0
  tcp_state.feed key, segment, flags, seq

-- ── SNI Extraction Helpers ────────────────────────────────

tls_version_name = (ver) ->
  return nil unless ver
  switch ver
    when 0x0301 then "TLS1.0"
    when 0x0302 then "TLS1.1"
    when 0x0303 then "TLS1.2"
    when 0x0304 then "TLS1.3"
    else string.format("0x%04x", ver)

extract_supported_versions = (ext_data) ->
  return nil unless ext_data and #ext_data >= 2
  ok_sv, sv = pcall -> ipparse_supported_versions.parse ext_data, 1
  return nil unless ok_sv and sv

  if sv.versions and #sv.versions > 0
    best_ver = nil
    for ver in *sv.versions
      best_ver = ver if not best_ver or ver > best_ver
    return tls_version_name best_ver

  if sv.selected
    return tls_version_name sv.selected

  nil

--- Extract SNI from TLS ClientHello payload.
-- @tparam string payload Raw TLS record data starting with TLS record header
-- @treturn string|nil SNI hostname or nil
extract_sni_from_tls = (payload, ctx={}) ->
  tls_version = nil
  tls_record_version = nil
  tls_client_hello_version = nil
  tls_supported_version = nil
  if payload and #payload >= 5
    record_ver = payload\byte(2) * 256 + payload\byte(3)
    tls_record_version = tls_version_name record_ver
    tls_version = tls_record_version

  if payload and #payload >= 11
    ch_ver = payload\byte(10) * 256 + payload\byte(11)
    tls_client_hello_version = tls_version_name ch_ver
    tls_version = tls_client_hello_version or tls_version

  -- Métadonnées TLS du moment (closure : lit les versions au moment de l'appel).
  mk_meta = (path) -> {
    tls_version: tls_version
    tls_record_version: tls_record_version
    tls_client_hello_version: tls_client_hello_version
    tls_supported_version: tls_supported_version
    tls_parser_path: path
  }

  debug_tls = (action, extra=nil) ->
    e = mk_meta nil
    e.action = action
    e.pkt_id = ctx.pkt_id
    e.tls_len = payload and #payload or 0
    if extra
      for k, v in pairs extra
        e[k] = v
    log_debug -> e

  -- Échec : trace debug "tls_parse_<reason>" et renvoie le triplet d'erreur.
  fail = (path, reason, extra) ->
    debug_tls "tls_parse_#{reason}", extra
    nil, reason, mk_meta path

  debug_tls "tls_parse_start"
  unless payload and #payload >= 9
    return fail "none", "short_payload"

  -- Verify TLS record type = Handshake (0x16)
  record_type = payload\byte 1
  unless record_type == 0x16
    return fail "none", "not_handshake_record", { tls_record_type: string.format("0x%02x", record_type) }

  -- Handshake type = ClientHello (0x01) at offset 6
  hs_type = payload\byte 6
  unless hs_type == 0x01
    return fail "none", "not_client_hello", { hs_type: string.format("0x%02x", hs_type) }

  -- Try strict parse first (full ClientHello available in one packet), via
  -- ipparse. Le corps du ClientHello commence après l'en-tête de record TLS
  -- (5 octets) et l'en-tête de handshake (4 octets) → offset 10 (1-indexé).
  -- ipparse renvoie `extensions` SANS son préfixe de longueur 2 octets : on
  -- itère donc directement les entrées (type|len|data), comme l7.quic.session.
  success, client_hello_parsed = pcall -> ipparse_tls_client_hello.parse payload, 10
  if success and client_hello_parsed and client_hello_parsed.extensions and #client_hello_parsed.extensions > 0
    if client_hello_parsed.version
      tls_client_hello_version = tls_version_name client_hello_parsed.version
      tls_version = tls_client_hello_version or tls_record_version

    ext_data = client_hello_parsed.extensions
    i = 1
    while i + 3 <= #ext_data
      ext_type = (ext_data\byte i) * 256 + ext_data\byte(i + 1)
      ext_len  = (ext_data\byte(i + 2)) * 256 + ext_data\byte(i + 3)
      ext_payload_offset = i + 4
      break if ext_payload_offset + ext_len - 1 > #ext_data

      -- Extension type 0 = Server Name Indication
      if ext_type == 0
        sni_data = ext_data\sub ext_payload_offset, ext_payload_offset + ext_len - 1
        success_sni, sni_list = pcall -> ipparse_server_name.parse sni_data, 1
        if success_sni and sni_list and sni_list.name
          debug_tls "tls_parse_strict_sni_found", { sni: sni_list.name }
          return sni_list.name, nil, mk_meta "strict"

      if ext_type == 0x002b
        sv = extract_supported_versions ext_data\sub ext_payload_offset, ext_payload_offset + ext_len - 1
        if sv
          tls_supported_version = sv
          tls_version = tls_supported_version

      i = ext_payload_offset + ext_len

  -- Fallback parser tolerant to fragmented ClientHello packets.
  -- It only requires the prefix up to the SNI extension.
  offset = 10 -- TLS(5) + Handshake header(4) + Lua 1-indexing
  unless #payload >= offset + 33 -- version(2) + random(32)
    return fail "fallback", "fallback_short_random"

  offset += 34
  session_id_len = payload\byte offset
  unless session_id_len
    return fail "fallback", "fallback_no_session_id_len"
  offset += 1
  unless #payload >= offset + session_id_len - 1
    return fail "fallback", "fallback_short_session_id", { session_id_len: session_id_len }
  offset += session_id_len

  unless #payload >= offset + 1
    return fail "fallback", "fallback_short_cipher_len"
  cipher_suites_len = (payload\byte(offset) * 256) + payload\byte(offset + 1)
  offset += 2
  unless #payload >= offset + cipher_suites_len - 1
    return fail "fallback", "fallback_short_cipher_suites", { cipher_suites_len: cipher_suites_len }
  offset += cipher_suites_len

  unless #payload >= offset
    return fail "fallback", "fallback_short_compression_len"
  compression_len = payload\byte offset
  offset += 1
  unless #payload >= offset + compression_len - 1
    return fail "fallback", "fallback_short_compression", { compression_len: compression_len }
  offset += compression_len

  unless #payload >= offset + 1
    return fail "fallback", "fallback_short_extensions_len"
  extensions_len = (payload\byte(offset) * 256) + payload\byte(offset + 1)
  offset += 2

  ext_end = math.min #payload, offset + extensions_len - 1
  while offset + 3 <= ext_end
    ext_type = (payload\byte(offset) * 256) + payload\byte(offset + 1)
    ext_len = (payload\byte(offset + 2) * 256) + payload\byte(offset + 3)
    ext_data_start = offset + 4
    ext_data_end = math.min ext_end, ext_data_start + ext_len - 1
    break if ext_data_start > ext_end

    if ext_type == 0 -- server_name
      unless ext_data_end - ext_data_start + 1 >= 5
        return fail "fallback", "fallback_short_sni_ext"
      name_list_len = (payload\byte(ext_data_start) * 256) + payload\byte(ext_data_start + 1)
      name_type = payload\byte(ext_data_start + 2)
      name_len = (payload\byte(ext_data_start + 3) * 256) + payload\byte(ext_data_start + 4)
      name_start = ext_data_start + 5
      name_end = name_start + name_len - 1

      if name_type == 0 and name_len > 0 and name_end <= ext_data_end and name_len <= name_list_len
        sni = payload\sub name_start, name_end
        debug_tls "tls_parse_fallback_sni_found", { sni: sni }
        return sni, nil, mk_meta "fallback"

    if ext_type == 0x002b
      sv = extract_supported_versions payload\sub ext_data_start, ext_data_end
      if sv
        tls_supported_version = sv
        tls_version = tls_supported_version

    offset = ext_data_start + ext_len

  debug_tls "tls_parse_no_sni"
  nil, "no_sni_in_extensions", mk_meta "fallback"

--- Extract SNI from QUIC Initial packet crypto data.
-- @tparam string quic_payload Raw QUIC data starting at L4 payload
-- @treturn string|nil SNI hostname or nil
extract_sni_from_quic = (quic_payload, session_key=nil) ->
  return nil, "short_payload", { quic_parser_path: "none" } unless quic_payload and #quic_payload >= 5

  success, quic_header = pcall -> ipparse_quic.parse quic_payload, 1
  unless success and quic_header
    return nil, "quic_header_parse_failed", { quic_parser_path: "none" }
  unless quic_header.long_header
    return nil, "quic_short_header", { quic_parser_path: "none" }
  unless quic_header.pkt_type == 0x00
    return nil, "quic_not_initial", { quic_parser_path: "none" }

  now = os.time!
  -- Éviction TTL : balaye d'abord les flux dormants, puis le plafond dur.
  prune_quic_sessions now if quic_sessions_count >= QUIC_SESSION_MAX

  -- Helper de suppression cohérent (état + compteur + horodatage).
  drop_session = ->
    if session_key and quic_sessions[session_key]
      quic_sessions[session_key] = nil
      quic_sessions_seen[session_key] = nil
      quic_sessions_count -= 1

  session = nil
  if session_key and quic_sessions[session_key]
    session = quic_sessions[session_key]
  else
    ok_session, session_or_err = pcall -> ipparse_quic_session.new!
    unless ok_session and session_or_err
      return nil, "quic_session_init_failed:#{session_or_err}", { quic_parser_path: "session" }
    session = session_or_err
    if session_key
      quic_sessions[session_key] = session
      quic_sessions_count += 1
  quic_sessions_seen[session_key] = now if session_key

  ok_push, push_err = session\push quic_payload
  unless ok_push
    drop_session!
    return nil, "quic_push_failed:#{push_err}", { quic_parser_path: "session" }

  sni = session\sni!
  if sni and #sni > 0
    drop_session!
    return sni, nil, { quic_parser_path: "session" }
  nil, "quic_no_sni_in_crypto", { quic_parser_path: "session" }

quic_flow_key = (src_ip, dst_ip, src_port, dst_port) ->
  a = string.format "%s|%d", src_ip or "unknown", src_port or 0
  b = string.format "%s|%d", dst_ip or "unknown", dst_port or 0
  if a <= b
    "#{a}|#{b}"
  else
    "#{b}|#{a}"

--- Format MAC address for logging
-- @tparam string mac_raw 6-byte MAC address
-- @treturn string Formatted MAC like "aa:bb:cc:dd:ee:ff"
format_mac = (mac_raw) ->
  return "unknown" unless mac_raw and #mac_raw == 6
  mac2s mac_raw

--- Format IP address for logging (délègue à ipparse ip2s).
-- @tparam number version IP version (4 or 6)
-- @tparam string ip_raw Raw IP bytes
-- @treturn string Formatted IP address
format_ip = (version, ip_raw) ->
  return "unknown" unless ip_raw and (version == 4 or version == 6)
  return "unknown" if version == 4 and #ip_raw < 4
  ipparse_ip.ip2s ip_raw

tsv_field = (v) ->
  s = if v ~= nil then tostring v else ""
  if #s == 0 then "-" else s

write_sni_event = (decision, fields) ->
  return unless events_wfd
  line = table.concat({
    tostring os.time!
    tsv_field decision
    tsv_field fields.sni
    tsv_field fields.mac_src
    tsv_field fields.src_ip
    tsv_field fields.dst_ip
    tsv_field fields.vlan
    tsv_field fields.user
    tsv_field fields.af
    tsv_field fields.reason
    tsv_field fields.rule
  }, "\t") .. "\n"
  libc.write events_wfd, line, #line

normalize_sni = (sni) ->
  return nil unless sni and #sni > 0
  sni\lower!\gsub "%.+$", ""

protocol_in_scope = (policy, l4_proto) ->
  return false unless policy
  p = policy.protocols or "both"
  return true if p == "both"
  return l4_proto == "tcp" if p == "tcp-only"
  return l4_proto == "udp" if p == "quic-only"
  false

is_mail_ssl_port = (port) ->
  return true if port == 465  -- SMTPS
  return true if port == 587  -- STARTTLS (SMTP)
  return true if port == 993  -- IMAPS
  return true if port == 995  -- POP3S
  false

is_ipv6 = (ip) ->
  ip and ip\find ":", 1, true

--- Renvoie la table decide_meta complète (ou nil + raison) pour un req SNI.
-- @treturn table|nil meta
-- @treturn string|nil err  Raison de l'indisponibilité (si meta nil).
safe_filter_decide = (req) ->
  return nil, "filter_unavailable" unless filter and filter.decide_meta
  ok, meta = pcall filter.decide_meta, req
  return nil, "filter_decide_exception" unless ok
  meta

ensure_nft_modules = ->
  unless cmd_for
    ok_cmd, nft_queue = pcall require, "nft_queue"
    return false, "nft_queue_require_failed" unless ok_cmd and nft_queue and nft_queue.cmd_for
    cmd_for = nft_queue.cmd_for

  unless run_cmd
    ok_nft, nft_mod = pcall require, "nft"
    return false, "nft_require_failed" unless ok_nft and nft_mod and nft_mod.run_cmd
    run_cmd = nft_mod.run_cmd

  true, nil

-- Réinitialise le cache des modules nft (utile pour les tests avec stubs)
reset_nft_modules = ->
  cmd_for = nil
  run_cmd = nil

apply_nft_allow = (src_ip, dst_ip, mac, policy, rule_id) ->
  ok_mods, mod_err = ensure_nft_modules!
  return false, mod_err unless ok_mods
  return false, "invalid_ip_pair" unless src_ip and dst_ip and src_ip != "unknown" and dst_ip != "unknown"
  return false, "family_mismatch" if is_ipv6(src_ip) != is_ipv6(dst_ip)

  ip_kind = if is_ipv6(dst_ip) then "ip6" else "ip4"
  mac_kind = if is_ipv6(dst_ip) then "mac6" else "mac4"
  cmds = {}

  ip_cmd = cmd_for ip_kind, src_ip, dst_ip, rule_id, SNI_TIMEOUT
  if ip_cmd
    cmds[#cmds + 1] = ip_cmd
  else
    return false, "nft_cmd_build_failed"

  if mac and mac != "unknown" and mac != "00:00:00:00:00:00"
    mac_cmd = cmd_for mac_kind, mac, dst_ip, rule_id, SNI_TIMEOUT
    cmds[#cmds + 1] = mac_cmd if mac_cmd

  ok, err = run_cmd table.concat(cmds, "\n"), { quiet: true }
  return true if ok
  return false, err or "nft_cmd_failed" if policy and policy.nft_failure_policy == "fail-closed"
  true, "nft_failed_fail_open"

-- ── Enforcement SNI : redirect (cname) et second avis (validate) ──────────
--
-- worker_tls applique au SNI la même protection que le DNS. Un verdict `allow`
-- du filtre ne suffit pas : une règle SafeSearch a un verdict allow mais réécrit
-- la RÉPONSE DNS (cname) ou délègue à un validateur. Comme on ne peut pas
-- réécrire de façon transparente un flux TLS/QUIC déjà dirigé vers une IP, on
-- BLOQUE (le client repasse alors par le DNS Custos, qui renvoie la bonne IP).

--- Décision symbolique à partir de la table decide_meta (fonction PURE, testable).
-- Ne fait aucune I/O : les cas "redirect"/"validate" sont résolus par l'appelant.
-- @tparam table meta Table renvoyée par filter.decide_meta.
-- @treturn string "accept" | "block" | "dnsonly" | "allow" | "redirect" | "validate"
sni_action_for = (meta) ->
  return "accept" unless meta              -- filtre indisponible → fail-open
  v = meta.verdict
  return "accept" if v == nil              -- exception filtre → fail-open
  return "block" if v == false
  return "dnsonly" if v == "dnsonly"
  -- v == true (ou tout autre truthy)
  return "redirect" if meta.redirects_destination
  return "validate" if meta.allow_modifiers and meta.allow_modifiers.validate
  "allow"

-- Charge paresseusement le validateur (second avis DNS).
ensure_validator = ->
  unless validator_mod
    ok, mod = pcall require, "doh.validator"
    return false, "validator_require_failed" unless ok and mod and mod.query_verdict
    validator_mod = mod
  true, nil

-- Charge paresseusement le module cname (résolution de la cible de redirection).
ensure_cname = ->
  unless cname_mod
    ok, mod = pcall require, "filter.actions.cname"
    return false, "cname_require_failed" unless ok and mod and mod.resolve_target_rrs
    cname_mod = mod
  true, nil

-- Construit une requête DNS A brute (wire format) pour un domaine donné.
build_validator_query = (domain) ->
  parts = {}
  txid = math.random 0, 0xFFFF
  hi = math.floor txid / 256
  lo = txid % 256
  -- En-tête : id, flags RD=0x0100, qdcount=1, autres=0.
  parts[#parts + 1] = string.char hi, lo, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  for label in domain\gmatch "[^.]+"
    parts[#parts + 1] = string.char #label
    parts[#parts + 1] = label
  parts[#parts + 1] = string.char 0
  parts[#parts + 1] = string.char 0x00, 0x01, 0x00, 0x01  -- QTYPE A, QCLASS IN
  table.concat parts

-- Évince les entrées de cache de verdict expirées (borne mémoire).
prune_sni_verdicts = (now=os.time!) ->
  removed = 0
  for domain, entry in pairs sni_verdict_cache
    if entry.expires_at <= now
      sni_verdict_cache[domain] = nil
      removed += 1
  sni_verdict_count -= removed
  removed

-- Réinitialise le cache de verdict (test seam).
reset_sni_verdicts = ->
  for k in pairs sni_verdict_cache
    sni_verdict_cache[k] = nil
  sni_verdict_count = 0

-- Injecte l'état du validateur/cname (test seam : permet de fournir des mocks
-- sans dépendre du vrai client UDP/DoH ni de config).
set_validator_state = (state={}) ->
  validator_mod = state.validator_mod if state.validator_mod != nil
  cname_mod = state.cname_mod if state.cname_mod != nil
  second_opinion_cfg = state.second_opinion_cfg if state.second_opinion_cfg != nil
  filter_cfg = state.filter_cfg if state.filter_cfg != nil

--- Interroge le validateur (second avis) pour un domaine SNI, avec cache.
-- Fail-open : validateur indisponible/muet → non bloqué (cohérent avec le DNS).
-- @tparam string domain     Domaine (SNI normalisé).
-- @tparam table|boolean validate_modifier Résolveurs per-règle, ou true (globaux).
-- @treturn boolean blocked
-- @treturn string|nil reason
validate_sni = (domain, validate_modifier) ->
  return false, nil unless domain and domain != ""
  now = os.time!
  cached = sni_verdict_cache[domain]
  if cached and cached.expires_at > now
    return cached.blocked, cached.reason

  ok_mod, mod_err = ensure_validator!
  return false, mod_err unless ok_mod

  resolvers = if type(validate_modifier) == "table"
    validate_modifier
  else
    second_opinion_cfg and second_opinion_cfg.resolvers
  return false, "no_validator_resolvers" unless resolvers and #resolvers > 0

  budget = (second_opinion_cfg and second_opinion_cfg.budget_ms) or 1000
  doh_budget = (second_opinion_cfg and second_opinion_cfg.doh_budget_ms) or 3000
  dns_raw = build_validator_query domain
  ok_q, blocked, reason = pcall validator_mod.query_verdict, dns_raw, resolvers, budget, doh_budget
  blocked = ok_q and blocked or false  -- exception → fail-open
  reason = ok_q and reason or nil

  ttl = (second_opinion_cfg and second_opinion_cfg.verdict_ttl_s) or SNI_VERDICT_TTL
  prune_sni_verdicts now if sni_verdict_count >= SNI_VERDICT_MAX
  unless sni_verdict_cache[domain]
    sni_verdict_count += 1
  sni_verdict_cache[domain] = { :blocked, :reason, expires_at: now + ttl }
  blocked, reason

--- Vérifie si l'IP de destination du flux est DÉJÀ une cible légitime du CNAME.
-- Cas du client au cache DNS périmé (mais correct) : il a résolu le domaine avant
-- la mise en place de la règle et pointe quand même sur l'IP SafeSearch → on
-- laisse passer plutôt que de bloquer inutilement.
-- @tparam string target  Cible CNAME (meta.cname_target).
-- @tparam string ip_dst  IP de destination du flux (string).
-- @tparam number version 4 ou 6.
-- @treturn boolean matched
-- @treturn boolean resolved  false si la cible n'a pas pu être résolue.
dst_matches_cname = (target, ip_dst, version) ->
  return false, false unless target and target != "" and ip_dst and ip_dst != "unknown"
  ok_mod = ensure_cname!
  return false, false unless ok_mod
  resolver_ip = cname_mod.pick_resolver_ip filter_cfg, nil
  ok_r, rrs = pcall cname_mod.resolve_target_rrs, filter_cfg, target, resolver_ip
  return false, false unless ok_r and rrs
  list = if version == 6 then rrs.aaaa else rrs.a
  return false, true unless list and #list > 0
  for rdata in *list
    return true, true if ipparse_ip.ip2s(rdata) == ip_dst
  false, true

-- ── Main Packet Handler ──────────────────────────────────

--- Main callback for SNI logger NFQUEUE.
-- Handles both TCP/443 (TLS) and UDP/443 (QUIC) packets.
handle_sni_packet = (qh_ptr, nfad, pkt_id) ->
  log_debug -> { action: "callback", pkt_id: pkt_id }

  -- 1. Extract L2 (MAC source)
  l2 = get_l2 nfad
  unless l2
    log_debug -> { action: "no_l2", pkt_id: pkt_id }
    return NF_ACCEPT

  -- 2. Extract payload
  payload_ptr = ffi.new "unsigned char*[1]"
  payload_len = libnfq.nfq_get_payload nfad, payload_ptr
  if payload_len <= 0
    log_debug -> { action: "no_payload", pkt_id: pkt_id }
    return NF_ACCEPT

  raw = ffi.string payload_ptr[0], payload_len

  -- 3. Parse IP header
  ip, err = ipparse_ip.parse raw, 1
  unless ip
    log_debug -> { action: "ip_parse_failed", pkt_id: pkt_id }
    return NF_ACCEPT

  -- 4. Determine protocol and extract SNI
  protocol_name = nil
  l4_proto = nil
  sni = nil
  src_port = nil
  dst_port = nil
  tls_reason = nil
  tls_meta = nil

  if ip.protocol == 6  -- TCP
    l4_proto = "tcp"
    -- Parse TCP header
    success, tcp = pcall -> ipparse_tcp.parse raw, ip.data_off
    unless success and tcp
      log_debug -> { action: "tcp_parse_failed", pkt_id: pkt_id }
      return NF_ACCEPT

    unless tcp.data_off and tcp.data_off >= 1
      log_debug -> { action: "tcp_data_off_invalid", pkt_id: pkt_id }
      return NF_ACCEPT

    src_port = tcp.spt
    dst_port = tcp.dpt
    protocol_name = if is_mail_ssl_port dst_port
      switch dst_port
        when 465 then "smtps"
        when 587 then "smtp_starttls"
        when 993 then "imaps"
        when 995 then "pop3s"
        else "mail_ssl"
    else "https"

    if tcp.data_off > #raw
      log_debug -> { action: "tcp_no_payload", pkt_id: pkt_id }
      return NF_ACCEPT

    -- Réassemble le ClientHello potentiellement fragmenté sur plusieurs
    -- segments TCP avant extraction du SNI (cf. tls_record_complete).
    segment = raw\sub tcp.data_off
    src_ip_k = format_ip ip.version, ip.src
    dst_ip_k = format_ip ip.version, ip.dst
    tcp_key = "#{src_ip_k}|#{src_port}|#{dst_ip_k}|#{dst_port}"
    tls_payload = feed_tls_segment tcp_key, segment, tcp.flags, tcp.seq_n
    -- Segment de contrôle (FIN/RST), payload vide ou ClientHello incomplet :
    -- laisser passer en attendant la suite du flux.
    unless tls_payload
      log_debug -> { action: "tcp_buffering", pkt_id: pkt_id }
      return NF_ACCEPT

    -- Ignore non-TLS Handshake records and non-ClientHello Handshake messages.
    -- In integral mode, all ACK packets hit this queue; after tcp_stream clears the
    -- ClientHello session, subsequent Handshake records (Client Key Exchange, Finished…)
    -- from the same connection would otherwise reach extract_sni, fail to find SNI, and
    -- get dropped in strict-443 mode.
    ok_rec, tls_rec = pcall -> ipparse_tls.parse tls_payload, 1
    unless ok_rec and tls_rec and tls_rec.type == ipparse_tls.record_types.handshake
      log_debug -> { action: "tcp_not_tls_handshake", pkt_id: pkt_id }
      return NF_ACCEPT
    ok_hs, hs_hdr = pcall -> ipparse_tls_handshake.parse tls_payload, tls_rec.data_off
    unless ok_hs and hs_hdr and hs_hdr.type == ipparse_tls_handshake.message_types.client_hello
      log_debug -> { action: "tcp_not_client_hello", pkt_id: pkt_id }
      return NF_ACCEPT

    sni, tls_reason, tls_meta = extract_sni_from_tls tls_payload, { pkt_id: pkt_id }

  elseif ip.protocol == 17  -- UDP
    l4_proto = "udp"
    -- Parse UDP header
    success, udp = pcall -> ipparse_udp.parse raw, ip.data_off
    unless success and udp
      log_debug -> { action: "udp_parse_failed", pkt_id: pkt_id }
      return NF_ACCEPT

    src_port = udp.spt
    dst_port = udp.dpt
    protocol_name = "quic"

    -- Extract SNI from QUIC payload
    if udp.data_off <= #raw
      quic_payload = raw\sub udp.data_off
      src_ip = format_ip ip.version, ip.src
      dst_ip = format_ip ip.version, ip.dst
      quic_session_key = quic_flow_key src_ip, dst_ip, src_port, dst_port
      sni, tls_reason, tls_meta = extract_sni_from_quic quic_payload, quic_session_key

  mac_str = format_mac l2.mac_raw
  ip_src_str = format_ip ip.version, ip.src
  ip_dst_str = format_ip ip.version, ip.dst
  af = if ip.version == 6 then "ipv6" else "ipv4"
  strict_mode = sni_policy and sni_policy.mode == "strict-443"
  in_scope = protocol_in_scope sni_policy, l4_proto
  mail_port = is_mail_ssl_port dst_port
  -- Source du verdict pour les logs : distingue le transport (TLS sur TCP,
  -- QUIC sur UDP) afin que allow/deny indiquent d'où tombe la décision.
  worker_src = if l4_proto == "udp" then "sni-quic" else "sni-tls"

  -- Champs communs d'un événement SNI (TSV) pour ce paquet.
  sni_event = (decision, sni_val, reason, rule) ->
    write_sni_event decision, {
      sni: sni_val, mac_src: mac_str, src_ip: ip_src_str, dst_ip: ip_dst_str
      vlan: l2.vlan, user: nil, af: af, :reason, :rule
    }

  -- Recopie les métadonnées TLS/QUIC du parseur dans une table de log.
  with_meta = (e) ->
    if tls_meta
      e.tls_version             = tls_meta.tls_version
      e.tls_record_version      = tls_meta.tls_record_version
      e.tls_client_hello_version = tls_meta.tls_client_hello_version
      e.tls_supported_version   = tls_meta.tls_supported_version
      e.tls_parser_path         = tls_meta.tls_parser_path
      e.quic_parser_path        = tls_meta.quic_parser_path
    e

  unless sni
    if protocol_name == "quic" and tls_reason and (
      tls_reason\match("^quic_session_init_failed") or tls_reason\match("^quic_push_failed")
    )
      log_warn -> {
        action: "quic_parse_failed"
        pkt_id: pkt_id
        reason: tls_reason
        quic_parser_path: tls_meta and tls_meta.quic_parser_path
      }
    if strict_mode and in_scope and not mail_port
      log_block -> {
        action: "sni_verdict_block_no_sni"
        worker: worker_src
        pkt_id: pkt_id
        protocol: protocol_name
        l4_proto: l4_proto
        ip_src: ip_src_str
        ip_dst: ip_dst_str
        port_src: src_port
        port_dst: dst_port
        reason: tls_reason or "no_sni"
      }
      sni_event "block", nil, tls_reason or "no_sni", "strict-443/no_sni"
      return NF_DROP
    if mail_port and strict_mode and in_scope
      log_warn -> with_meta {
        action: "sni_verdict_warn_no_sni_mail"
        pkt_id: pkt_id
        protocol: protocol_name
        l4_proto: l4_proto
        ip_src: ip_src_str
        ip_dst: ip_dst_str
        port_src: src_port
        port_dst: dst_port
        reason: tls_reason or "no_sni"
      }
      sni_event "warn", nil, tls_reason or "no_sni", "mail_ssl/no_sni"
      return NF_ACCEPT
    log_debug -> with_meta {
      action: "sni_verdict_skip_no_sni", pkt_id: pkt_id, protocol: protocol_name, l4_proto: l4_proto, reason: tls_reason
    }
    return NF_ACCEPT

  sni_norm = normalize_sni sni
  log_info -> with_meta {
    action: "sni_captured"
    protocol: protocol_name
    l4_proto: l4_proto
    sni: sni_norm or sni
    mac_src: mac_str
    ip_src: ip_src_str
    ip_dst: ip_dst_str
    port_src: src_port
    port_dst: dst_port
  }

  req = {
    domain: sni_norm or sni
    src_ip: ip_src_str
    mac: mac_str
    vlan: l2.vlan
    ts: os.time!
    user: user_for_mac mac_str, ip_src_str, auth_sessions_file
  }
  meta, decide_err = safe_filter_decide req
  decide_reason = (meta and meta.reason) or decide_err
  decide_rule = meta and meta.rule_id

  if not in_scope
    log_debug -> {
      action: "sni_verdict_skip_protocol"
      pkt_id: pkt_id
      protocol: protocol_name
      l4_proto: l4_proto
      sni: sni_norm or sni
      policy_protocols: sni_policy and sni_policy.protocols or "both"
    }
    return NF_ACCEPT

  action = sni_action_for meta

  -- Filtre indisponible / exception → fail-open (cohérent avec le chemin DNS).
  if action == "accept"
    log_warn -> {
      action: "sni_verdict_skip_filter_error"
      pkt_id: pkt_id
      protocol: protocol_name
      l4_proto: l4_proto
      sni: sni_norm or sni
      reason: decide_reason or "filter_error"
    }
    return NF_ACCEPT

  -- Branche refus : en strict-443 on bloque (log + event + DROP), sinon on
  -- trace en debug et on laisse passer.
  block_or_skip = (action_block, action_skip, reason, event_rule) ->
    if strict_mode
      log_block -> {
        action: action_block
        worker: worker_src
        pkt_id: pkt_id
        protocol: protocol_name
        l4_proto: l4_proto
        sni: sni_norm or sni
        ip_src: ip_src_str
        ip_dst: ip_dst_str
        mac_src: mac_str
        :reason
        rule: decide_rule
      }
      sni_event "block", sni_norm or sni, reason, event_rule
      return NF_DROP
    log_debug -> {
      action: action_skip
      pkt_id: pkt_id
      protocol: protocol_name
      l4_proto: l4_proto
      sni: sni_norm or sni
      :reason
      rule: decide_rule
    }
    NF_ACCEPT

  -- Autorisation effective : injecte les sets nft puis ACCEPT.
  do_allow = ->
    ok_nft, nft_reason = apply_nft_allow ip_src_str, ip_dst_str, mac_str, sni_policy, decide_rule
    unless ok_nft
      log_block -> {
        action: "sni_verdict_nft_failed"
        worker: worker_src
        pkt_id: pkt_id
        protocol: protocol_name
        l4_proto: l4_proto
        sni: sni_norm or sni
        ip_src: ip_src_str
        ip_dst: ip_dst_str
        mac_src: mac_str
        reason: nft_reason
        nft_failure_policy: sni_policy and sni_policy.nft_failure_policy or "fail-closed"
      }
      sni_event "block", sni_norm or sni, nft_reason, decide_rule or "nft_insert_failed"
      return NF_DROP if (sni_policy and sni_policy.nft_failure_policy or "fail-closed") == "fail-closed"
      return NF_ACCEPT

    log_allow -> with_meta {
      action: "sni_verdict_allow"
      worker: worker_src
      protocol: protocol_name
      l4_proto: l4_proto
      sni: sni_norm or sni
      ip_src: ip_src_str
      ip_dst: ip_dst_str
      mac_src: mac_str
      port_src: src_port
      port_dst: dst_port
      filter_reason: decide_reason
      rule: decide_rule
      nft_outcome: nft_reason or "ok"
    }
    sni_event "allow", sni_norm or sni, decide_reason, decide_rule
    NF_ACCEPT

  switch action
    when "allow"
      return do_allow!
    when "redirect"
      -- Le DNS aurait réécrit la réponse (SafeSearch/cname) vers une autre IP.
      -- On ne peut pas rediriger un flux déjà établi → bloquer, SAUF si le client
      -- pointe déjà sur l'IP cible (cache DNS périmé mais correct).
      matched, resolved = dst_matches_cname meta.cname_target, ip_dst_str, ip.version
      return do_allow! if matched
      reason = if resolved then "sni_redirect_wrong_ip" else "sni_redirect_target_unresolved"
      return block_or_skip "sni_verdict_block_redirect", "sni_verdict_skip_redirect",
        decide_reason or reason, "sni_redirect_blocked"
    when "validate"
      blocked, vreason = validate_sni (sni_norm or sni), meta.allow_modifiers.validate
      return do_allow! unless blocked
      return block_or_skip "sni_verdict_block_validator", "sni_verdict_skip_validator",
        vreason or "validator_blocked", "sni_validator_blocked"
    when "dnsonly"
      return block_or_skip "sni_verdict_block_dnsonly", "sni_verdict_skip_dnsonly",
        decide_reason or "dnsonly", decide_rule or "dnsonly"
    else  -- "block"
      return block_or_skip "sni_verdict_block", "sni_verdict_skip",
        decide_reason or "denied", decide_rule

--- Entry point for the worker.
-- @tparam number queue_num Queue number
run = (queue_num, ev_wfd=nil, filter_data=nil) ->
  set_action_prefix "sni_"
  events_wfd = ev_wfd

  ok_filter, filter_or_err = pcall require, "filter"
  if ok_filter and filter_or_err
    filter = filter_or_err
    -- Initialize filter with data passed from main.moon
    if filter_data
      filter.rules = filter_data.rules
      filter.auth_cfg_cache = filter_data.auth_cfg_cache
      filter.sni_cfg_cache  = filter_data.sni_cfg_cache
      filter.decision_cfg = filter_data.decision_cfg
    auth_cfg = if filter.get_auth_cfg then filter.get_auth_cfg! else {}
    auth_sessions_file = auth_cfg.sessions_file or auth_sessions_file
    sni_policy = if filter.get_sni_cfg then filter.get_sni_cfg! else {}
  else
    filter = nil
    sni_policy = {}
    log_warn -> { action: "filter_require_failed", err: tostring(filter_or_err) }
  sni_policy.enabled = if sni_policy.enabled == nil then true else not not sni_policy.enabled
  sni_policy.mode = sni_policy.mode or "strict-443"
  sni_policy.protocols = sni_policy.protocols or "both"
  sni_policy.nft_failure_policy = sni_policy.nft_failure_policy or "fail-closed"

  -- Config pour le second avis (validate) et la résolution de cible cname,
  -- appliqués au SNI à l'identique du DNS.
  ok_cfg, full_cfg = pcall require, "config"
  if ok_cfg and full_cfg
    filter_cfg = full_cfg
    second_opinion_cfg = full_cfg.second_opinion
  log_info -> { action: "starting", queue: queue_num }

  unless sni_policy.enabled
    log_info -> { action: "disabled", queue: queue_num }
    return run_queue tonumber(queue_num), (qh_ptr, nfad, pkt_id) -> NF_ACCEPT

  log_info -> {
    action: "policy_loaded"
    queue: queue_num
    mode: sni_policy.mode
    protocols: sni_policy.protocols
    nft_failure_policy: sni_policy.nft_failure_policy
  }
  run_queue tonumber(queue_num), handle_sni_packet

{
  :run, :normalize_sni, :protocol_in_scope, :apply_nft_allow, :reset_nft_modules
  :extract_sni_from_tls, :extract_sni_from_quic, :quic_flow_key
  :prune_quic_sessions, :reset_quic_sessions, :seed_quic_session, :quic_session_count
  :reset_tcp_sessions, :feed_tls_segment
  :sni_action_for, :validate_sni, :dst_matches_cname, :build_validator_query
  :prune_sni_verdicts, :reset_sni_verdicts, :set_validator_state
}
