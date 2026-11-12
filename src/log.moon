-- src/log.moon
-- Logging structuré vers stdout.
-- Format : [epoch] [pid] LEVEL key=value key=value ...
-- Chaque write() est atomique pour les messages <= PIPE_BUF (4096 octets)
-- sur un pipe : compatible procd (logread) et systemd-journald.
-- Les champs sont en key=value pour faciliter l'ingestion par des outils
-- comme lnav, grok ou un simple awk.
--
-- Rate-limiting intégré : les messages répétitifs (même action + champs
-- discriminants) sont supprimés pendant une fenêtre configurable. Le premier
-- message après la fenêtre inclut le champ `suppressed=N`.

{ :ffi, :libc } = require "ffi_defs"
config = require "config"

bit = require "bit"

STDOUT_FILENO = 1
CLOCK_MONOTONIC = 1

ts  = ffi.new "timespec_t"

-- ── Instrumentation optionnelle du coût d'écriture ────────────────
-- Mesure la durée du `libc.write` de chaque ligne (benchmark). Désactivée
-- par défaut : quand elle est off, AUCUN appel d'horloge n'est ajouté au
-- chemin nominal (la seule horloge existante reste celle de l'epoch).
-- L'activation passe par `set_timing` (appelé une fois au démarrage par
-- main.moon, après lecture de la config), jamais par un `require "config"`
-- ici : ce module est requis très tôt, avant que la décision de benchmark
-- ne soit arrêtée, et un `require` en hot-path coûterait ~150 ns/ligne.
_timing_enabled = false
_last_write_us  = 0
_timing_start   = ffi.new "timespec_t"
_timing_end     = ffi.new "timespec_t"

-- Mappage des niveaux de log vers des valeurs numériques
-- (Plus la valeur est élevée, plus le log est verbeux)
LOG_LEVEL_MAP = {
  EMERG:  8
  ALERT:  7
  CRIT:   6
  ERROR:  5
  WARN:   4
  NOTICE: 3
  INFO:   2
  DEBUG:  1
  ALLOW:  3  -- Par défaut, ALLOW est au niveau NOTICE
  BLOCK:  4  -- Par défaut, BLOCK est au niveau WARN
  TRACE:  0  -- Plus verbeux que DEBUG (et non au-dessus d'ERROR)
}

-- Niveau de log configuré, converti en numérique
CURRENT_LOG_LEVEL_NUM = LOG_LEVEL_MAP[config.runtime.log_level] or LOG_LEVEL_MAP.INFO

--- Active/désactive la mesure de durée des écritures de journal.
-- À appeler une fois au démarrage (main.moon), avant les forks, pour que
-- tous les workers héritent de la valeur par COW.
-- @tparam boolean enabled true pour instrumenter les `write` suivants
-- @treturn nil
set_timing = (enabled) ->
  _timing_enabled = enabled and true or false
  nil

--- Durée du dernier `write` de journal mesuré, en microsecondes.
-- Mesure NON récursive : la valeur est celle du `write` TERMINÉ avant l'appel
-- (une ligne ne peut pas porter sa propre durée). Retourne 0 quand
-- l'instrumentation est désactivée ou qu'aucune écriture n'a encore eu lieu.
-- @treturn number durée en µs (entier)
get_last_write_us = -> _last_write_us

-- Microsecondes monotones depuis boot (horloge réservée à l'instrumentation,
-- appelée uniquement quand `_timing_enabled` est vrai).
monotonic_us = ->
  libc.clock_gettime CLOCK_MONOTONIC, _timing_start
  tonumber(_timing_start.tv_sec) * 1000000 + math.floor(tonumber(_timing_start.tv_nsec) / 1000)

--- Retourne la valeur numérique d'un niveau de log.
-- @tparam string level Niveau de log (ex: "INFO", "WARN")
-- @treturn number Valeur numérique du niveau, ou 0 si inconnu
get_log_level_num = (level) -> LOG_LEVEL_MAP[level] or 0

--- Indique si un niveau serait effectivement émis (au-dessus du seuil courant).
-- Permet aux call-sites du hot path de sauter la construction du thunk (closure
-- + capture) lorsque le niveau est filtré — write_log filtre déjà, mais APRÈS
-- l'allocation de la closure.
-- @tparam string level Niveau de log (ex: "DEBUG")
-- @treturn boolean true si le niveau est actif
level_enabled = (level) -> get_log_level_num(level) >= CURRENT_LOG_LEVEL_NUM

-- ── Rate-limiting ─────────────────────────────────────────────────
-- Empreinte par défaut : niveau + action + **tous les champs présents sauf
-- les champs explicitement classés VOLATILS** (liste ci-dessous). Un champ
-- inconnu est traité comme une identité (prudence : mieux vaut une ligne en
-- trop qu'une information perdue), et le test garde-fou
-- `tests/unit/log_fields_spec.moon` impose que tout champ des tables
-- littérales de `src/**/*.moon` figure dans l'une des deux listes.
--
-- IDENTITÉ : distingue deux événements (objet, interface, set, règle, hôte,
-- chemin, code d'erreur…). VOLATIL : varie à chaque occurrence sans changer
-- la nature du message (pid, txid, fd, port source, séquence, durée,
-- compteur, taille, horodatage, texte libre).
RL_IDENTITY_KEYS = {
  "addr", "af", "alpn", "alt_path", "arch", "arg1", "arg2", "available", "backend"
  "bridge", "captive_ip4", "captive_ip6", "cert", "cert_cache", "cert_file"
  "cert_type", "client", "client_ip", "client_mac", "closed", "cmd"
  "cn", "cname_target", "condition", "configured", "conflict", "cseq_method", "ct", "custom_url"
  "dir", "direction", "dnsonly", "domain", "dst", "dst_ip", "enabled", "env_path"
  "err", "errno", "events_dir", "exit_code", "external_loaded", "fallback"
  "fallback_builtin", "families", "family", "file", "filter_reason", "forced", "frame_mac", "handle"
  "handshake_done"
  "has_ip", "has_mac", "hint", "host", "hostname", "hs_type"
  "ifindex", "ifname", "in_ifindex", "inherited", "inject_nft", "interfaces"
  "ip", "ip4", "ip6", "ip_dst", "ip_src", "ip_version"
  "ipv4", "ipv6", "items", "key", "key_file", "kind"
  "known_mac", "l4_proto", "limit", "list", "load_error", "local_ip"
  "mac", "mac_fallback", "mac_src", "max", "maxlen", "media_ip", "method"
  "mode", "modified", "name", "net", "new", "nft_compilable", "nft_err", "nft_failure_policy", "nft_outcome"
  "nft_rule_id", "ns_enabled", "obtained", "ok", "old", "packet_mac", "path", "payload_modified"
  "peer", "peer_ip", "peer_mac", "policy_protocols", "port", "port_dst", "probe_max"
  "proto", "protocol", "protocols", "qname", "qnames", "qtype"
  "queue", "quic_parser_path", "rc", "rcode", "reason", "records"
  "redirect_url4", "redirect_url6", "refused", "refused_kept", "refused_new", "reject_mark", "requested"
  "resolver", "resolver_ip", "resolvers", "resolution", "response"
  "ret", "retry_budget_skipped", "rl_shared", "role", "rule", "rule_id", "rule_kept", "rule_new", "rules"
  "section", "selected", "selected_mac", "sessions_file", "sip_method", "sip_status", "slots", "sni", "source"
  "src", "src_ip", "ssl_err", "status", "target", "tlla", "transient"
  "type", "upstream_ip", "upstream_port", "url", "user", "username"
  "verdict", "verify_tls", "version", "vlan", "worker", "worker_idx"
}

RL_VOLATILE_KEYS = {
  "ack_wait_us", "ack_workers", "acks", "addrlen", "age_h", "ancount", "answers"
  "attempt", "attempts", "avail", "body_bytes", "bytes", "cert_size"
  "client_fd", "client_port", "client_timeout", "conditions_compiled", "conditions_worker_only"
  "configured_rules", "corr"
  "count", "decoded_bytes", "dest_whitelist", "detail", "dport", "drain_ms", "dropped", "dst_port"
  "effective_rules", "entries", "evicted", "events_rfd", "events_wfd", "expires_in_s"
  "fd", "frames", "free_pct", "grace", "groups", "hour", "ignored"
  "ipc_fd", "ipc_retry_attempts", "ipc_retry_wait_ms", "key_size", "learn_rfd", "learn_wfd"
  "len", "listen_fd", "log_ms", "log_write_us", "match_ms", "max_age_hours", "max_attempts", "min_free_pct"
  "days_left", "msg", "need", "new_size", "not_after", "parent_pid", "parse_ms", "payload_len", "payload_ms", "pending_max"
  "pid", "pkt_id", "port_src", "pos", "q_to_response_ms", "query_bytes"
  "question_proc_ms", "question_response_rfd"
  "question_response_wfd", "question_response_workers", "raw", "removed", "removed_count", "resp_bytes", "response_entry_ms"
  "retry_after", "rfd", "revents", "rv", "sans_count", "sent", "seq", "size"
  "sock", "sockets", "sport", "src_port", "timeout"
  "timeout_ms", "total", "total_rules", "ts", "ttl", "ttl_s"
  "txid", "upstream_retries", "userlists", "users", "worker_only"
}

-- Ensembles d'appartenance pour le test garde-fou (et pour la résolution
-- d'un champ inconnu côté empreinte : absent des deux = identité).
RL_IDENTITY_SET = {}
for k in *RL_IDENTITY_KEYS
  RL_IDENTITY_SET[k] = true

RL_VOLATILE_SET = {}
for k in *RL_VOLATILE_KEYS
  RL_VOLATILE_SET[k] = true

-- Résolution : action complète, puis action sans le préfixe du worker, puis
-- règle par défaut du NIVEAU (même quand `action` est présent). Avant ce
-- correctif, une action non listée n'était jamais limitée : les entrées
-- `INFO:`/`DEBUG:` ne s'appliquaient qu'aux messages sans champ `action`.
--
-- Fenêtres : ERROR/CRIT/ALERT/EMERG 10 s (ne jamais masquer longtemps une
-- erreur), WARN/INFO/NOTICE 60 s, DEBUG/TRACE 30 s (fidélité de diagnostic),
-- ALLOW/BLOCK 30 s (une entrée par triplet MAC/domaine/type).
RL_CONFIG = {
  captive_redirect:   { keys: {"ip"},                        window: 60  }
  ALLOW:              { keys: {"mac_src", "qname", "qtype"}, window: 30  }
  BLOCK:              { keys: {"mac_src", "qname", "qtype"}, window: 30  }
  no_ipv6_for_client: { keys: {"client"},                    window: 120 }
  no_ipv4_for_client: { keys: {"client"},                    window: 120 }
  response_dnsonly:   { keys: {"dst_ip", "qnames"},          window: 30  }
  -- Échecs d'authentification : jamais exemptés (force brute = inondation
  -- volontaire), mais bornés par client et utilisateur. `err` reste
  -- discriminant pour ne pas masquer la cause (nonce expiré vs invalide).
  -- Sites : handlers.moon:120,128,137.
  server_login_nonce_rejected:   { keys: {"ip", "user", "err"}, window: 60 }
  server_login_plaintext_refused: { keys: {"ip", "user"},       window: 60 }
  server_login_mac_missing:      { keys: {"ip", "mac"},         window: 60 }
  -- Audit de l'interface admin : une tentative refusée (non admin,
  -- validation, conflit) est bornée par client et par raison ; les
  -- modifications elles-mêmes sont dans RL_NEVER_LIMIT ci-dessous.
  webui_change_refused:          { keys: {"peer", "reason"},    window: 60 }
  EMERG:              { keys: RL_IDENTITY_KEYS,              window: 10  }
  ALERT:              { keys: RL_IDENTITY_KEYS,              window: 10  }
  CRIT:               { keys: RL_IDENTITY_KEYS,              window: 10  }
  ERROR:              { keys: RL_IDENTITY_KEYS,              window: 10  }
  WARN:               { keys: RL_IDENTITY_KEYS,              window: 60  }
  NOTICE:             { keys: RL_IDENTITY_KEYS,              window: 60  }
  INFO:               { keys: RL_IDENTITY_KEYS,              window: 60  }
  DEBUG:              { keys: RL_IDENTITY_KEYS,              window: 30  }
  TRACE:              { keys: RL_IDENTITY_KEYS,              window: 30  }
  -- Observabilité des anomalies d'appariement question/réponse. `keys: {}`
  -- agrège par action seule (aucun champ discriminant) : au plus une ligne par
  -- fenêtre, occurrences reportées dans `suppressed=N`. Fenêtre 10 s (plus
  -- courte que le défaut INFO de 60 s) : un événement isolé est toujours
  -- visible, une rafale de réponses orphelines (400/s) coûte au plus 1 ligne
  -- / 10 s. L'état du limiteur est partagé entre processus (table mmap), donc
  -- le plafond vaut tous workers confondus. La résolution essaie l'action
  -- complète puis sans le préfixe du worker (`response_`, `questions_`…) : ces
  -- entrées s'appliquent donc aussi aux actions préfixées.
  response_orphan_dropped:          { keys: {}, window: 10 }
  ipc_pending_overwrite:            { keys: {}, window: 10 }
  ipc_pending_overwrite_divergent:  { keys: {}, window: 10 }
  pending_evicted:                  { keys: {}, window: 10 }
  -- Tube IPC question→réponse durablement plein (worker réponses bloqué ou
  -- file NFQUEUE inactive, cf. docs/agents/perf.md §12) : une ligne par
  -- DESTINATAIRE et par fenêtre. `fd` est volatile (le défaut WARN l'ignore) et
  -- `ipc_fd` ne l'est pas : sans clé explicite, la saturation d'un tube
  -- masquerait celle d'un autre. Émis par ipc.write_with_retry_all.
  ipc_write_saturated:              { keys: {"ipc_fd"}, window: 60 }
}

-- Actions de cycle de vie jamais limitées : un crash répété (`worker_died`,
-- `child_crashed`) ou un rechargement de config ne doit jamais disparaître
-- derrière une fenêtre de suppression, même s'il se répète. Ces actions sont
-- rares hors boucle de crash, donc les laisser passer ne peut pas noyer les
-- logs. La comparaison se fait aussi après strip du préfixe worker.
RL_NEVER_LIMIT = {
  -- Instrumentation : `runtime.benchmark` ne doit jamais être rendu muet.
  -- Sur un banc à qname fixe, la règle ALLOW/BLOCK (mac_src/qname/qtype, 30 s)
  -- ne garderait qu'un échantillon par triplet et par fenêtre : les mesures
  -- (q_to_response_ms, drain_ms, parse_ms, match_ms…) des échantillons
  -- supprimés seraient perdues, c'est-à-dire l'objet même de l'option. Le
  -- préfixe worker `response_` est retiré avant comparaison.
  dns_benchmark:               true
  -- Diagnostic du limiteur lui-même : ne doit jamais être supprimé par le
  -- limiteur dont il signale la panne.
  log_rl_mmap_failed:          true
  log_rl_saturated:            true
  worker_died:                 true
  child_crashed:               true
  worker_started:              true
  worker_stopping:             true
  worker_start:                true
  supervisor_running:          true
  supervisor_sigterm:          true
  supervisor_sighup_reload:    true
  supervisor_sighup_kill:      true
  supervisor_sighup_refork:    true
  supervisor_sighup_forward_auth: true
  "dns-filter_start":          true
  config_source:               true
  config_external_missing:     true
  -- Audit de sécurité : une connexion, une déconnexion/expiration de session
  -- ou un changement de mot de passe ne doivent jamais disparaître derrière
  -- une fenêtre, même sous rafale. Sites : auth/handlers.moon:140 (login),
  -- :276 (bye/grâce), :221 (session invalidée), :427 (mot de passe) ;
  -- auth/user_sessions.moon:74 (expiration), :128 (retrait). Les échecs
  -- d'authentification ne sont PAS
  -- ici : ils restent limités par (ip, user) via RL_CONFIG (force brute).
  server_login_success:        true
  server_password_changed:     true
  server_bye_grace:            true
  server_ping_session_invalidated: true
  user_session_expired:        true
  user_session_removed:        true
  -- Audit des modifications faites depuis l'interface d'admin (webui) :
  -- jamais supprimées, même sous rafale (une modification d'état ne doit pas
  -- disparaître derrière une fenêtre). Les refus sont, eux, limités par
  -- (peer, reason) via RL_CONFIG (`webui_change_refused`). L'audit webui
  -- efface le préfixe `auth_` dans son enfant AUTH-conn (webui/audit.moon),
  -- donc ces actions sont émises telles quelles.
  webui_config_saved:          true
  webui_nets_saved:            true
  webui_nets_deleted:          true
  webui_macs_saved:            true
  webui_macs_deleted:          true
  webui_users_saved:           true
  webui_users_deleted:         true
  webui_times_saved:           true
  webui_times_deleted:         true
  webui_decision_saved:        true
  webui_rule_saved:            true
  webui_rule_deleted:          true
  webui_rule_toggled:          true
  webui_rule_moved:            true
  webui_rules_reordered:       true
  webui_list_saved:            true
  webui_list_deleted:          true
  webui_list_renamed:          true
  webui_device_saved:          true
  webui_reload_requested:      true
}

-- ── État partagé entre processus ──────────────────────────────────
-- Table de hachage à taille fixe (4096 slots × 4 uint32 + en-tête de 2 mots =
-- 64 Kio) dans une zone mmap(MAP_SHARED|MAP_ANONYMOUS) créée au chargement du
-- module — donc dans le superviseur avant tout fork — et héritée par tous les
-- workers et leurs enfants. Les enfants AUTH/DoH forkés par connexion
-- partagent ainsi le même état, contrairement à l'ancienne table Lua par
-- processus.
--
-- En-tête (2 uint32) : `hand` (main d'horloge de recyclage) et `saturated`
-- (nombre de log émis faute de slot recyclable, observable via `rl_stats`).
-- Slot : { hash, ts, expires, count }. `ts == 0` = libre ; `expires` est
-- l'échéance absolue (`ts + fenêtre de la règle`), ce qui permet de recycler un
-- slot dont la fenêtre est réellement passée sans connaître sa règle d'origine
-- — et donc de ne jamais supprimer une entrée encore vivante. On stocke le
-- hash 32 bits complet et on sonde linéairement : deux empreintes différentes
-- qui tombent dans le même slot occupent des slots distincts, aucune n'est
-- supprimée à tort. Sans verrou : les accès uint32 alignés ne peuvent pas être
-- déchirés ; une course peut produire une ligne en double ou un compteur
-- légèrement faux, jamais une corruption ni un blocage. Table saturée (sondage
-- épuisé sans slot libre ni expiré, puis balayage de la main d'horloge
-- infructueux) → on journalise sans supprimer et on incrémente le compteur.
RL_SLOTS = 4096
RL_SLOT_WORDS = 4
RL_HEADER_WORDS = 2
RL_HAND_SCAN = 32
RL_MMAP_WORDS = RL_HEADER_WORDS + RL_SLOTS * RL_SLOT_WORDS
RL_MMAP_BYTES = RL_MMAP_WORDS * 4
RL_PROBE_MAX = 8
PROT_READ = 1
PROT_WRITE = 2
MAP_SHARED = 0x01
-- MAP_ANONYMOUS n'a pas la même valeur selon l'architecture : 0x20 est la
-- valeur générique Linux (x86, x86_64, ARM), mais sur MIPS 0x20 est MAP_RENAME
-- et l'anonymat vaut 0x800. Un 0x20 codé en dur sur les routeurs ath79/ramips
-- (cibles supportées, cf. .agents/architecture.md) fait donc échouer
-- mmap(fd=-1) : plus d'état partagé, silencieusement. On choisit donc à
-- l'exécution depuis `jit.arch`. MAP_SHARED = 0x01 est commun à toutes les
-- architectures Linux.
_map_anonymous = (arch) ->
  if arch and arch\match "^mips" then 0x800 else 0x20

MAP_ANONYMOUS = _map_anonymous jit and jit.arch

_rl_base = nil
_rl = {}   -- repli uniquement si mmap échoue
_rl_fb_n = 0
_rl_fb_sat = 0
_rl_fallback_reason = nil
_rl_sat_warned = false
_rl_saved_base = nil

_ok, _err = pcall ->
  ptr = libc.mmap nil, RL_MMAP_BYTES, bit.bor(PROT_READ, PROT_WRITE), bit.bor(MAP_SHARED, MAP_ANONYMOUS), -1, 0
  if ptr != nil and ptr != ffi.cast("void*", -1)
    _rl_base = ffi.cast "uint32_t*", ptr
unless _rl_base
  _rl_fallback_reason = if _ok then "mmap_returned_MAP_FAILED" else tostring _err

-- Process-scoped action prefix (set once per worker, inherited by fork children).
_action_prefix = ""

--- Set a prefix prepended to every action= field in log output.
-- Actions already starting with the prefix are not double-prefixed.
-- @tparam string prefix  Short prefix string, e.g. "doh_"
-- @treturn nil
set_action_prefix = (prefix) ->
  _action_prefix = prefix or ""

--- Indique si une action de cycle de vie est exemptée de rate-limiting.
-- Teste l'action telle quelle puis sans le préfixe du worker courant.
-- @tparam string|nil action Champ `action` du message
-- @treturn boolean true si l'action ne doit jamais être supprimée
_rl_never_limited = (action) ->
  return false unless action
  return true if RL_NEVER_LIMIT[action]
  if _action_prefix != "" and action\sub(1, #_action_prefix) == _action_prefix
    return true if RL_NEVER_LIMIT[action\sub(#_action_prefix + 1)]
  false

--- Résout la configuration de rate-limiting d'un message.
-- Ordre : action complète, action sans le préfixe du worker, puis défaut du
-- niveau (qui s'applique même avec un champ `action`).
-- @tparam string level  Niveau de log
-- @tparam table  fields Champs du message
-- @treturn table|nil Configuration `{keys, window}` ou nil si aucune règle
_rl_resolve_cfg = (level, fields) ->
  action = fields.action
  if action
    cfg = RL_CONFIG[action]
    return cfg if cfg
    if _action_prefix != "" and action\sub(1, #_action_prefix) == _action_prefix
      cfg = RL_CONFIG[action\sub(#_action_prefix + 1)]
      return cfg if cfg
  RL_CONFIG[level]

--- Vérifie si un message doit être supprimé (rate-limiting).
-- @tparam string level  Niveau de log
-- @tparam table  fields Champs du message
-- @treturn number  -1 = supprimer ; 0 = première occurrence ; N>0 = N supprimés depuis dernier log
-- Construit le fingerprint de rate-limiting (action_key + champs discriminants).
-- Pour les règles explicites `keys: {...}`, concaténation directe dans l'ordre
-- de la liste (borné, ≤3 clés) plutôt qu'une table intermédiaire : ce code
-- s'exécute pour CHAQUE ALLOW/BLOCK, y compris ceux qui seront supprimés, donc
-- on évite l'allocation d'une table par paquet décidé.
-- Pour la règle par défaut (keys == RL_IDENTITY_KEYS), les noms de champs sont
-- triés avant concaténation : `pairs` n'a pas d'ordre stable et deux messages
-- identiques doivent produire la même clé. Cette branche n'est utilisée que
-- par le repli sans mmap (ou les tests), jamais sur le chemin chaud nominal.
-- Fonction pure, exportée pour le test unitaire.
-- @tparam string action_key Clé d'action (fields.action ou niveau)
-- @tparam table  fields     Champs du message
-- @tparam table  keys       Clés discriminantes (cfg.keys)
-- @treturn string Fingerprint
rl_fingerprint = (action_key, fields, keys) ->
  fp = action_key
  if keys == nil or keys == RL_IDENTITY_KEYS
    names = {}
    for k, v in pairs fields
      if k != "action" and not RL_VOLATILE_SET[k]
        names[#names + 1] = k
    table.sort names
    for k in *names
      fp ..= "|" .. k .. "=" .. tostring fields[k]
  else
    for k in *keys
      fp ..= "|" .. tostring fields[k]
  fp

-- Séparateurs précalculés pour le hash (évite une allocation de string par
-- champ et par message sur le chemin chaud ALLOW/BLOCK).
RL_SEP = {}
for k in *RL_IDENTITY_KEYS
  RL_SEP[k] = "\1" .. k .. "="

--- Hash 32 bits djb2 incrémental, sans allocation de table.
-- @tparam number h      Hash courant
-- @tparam string s      Chaîne à incorporer
-- @treturn number Hash mis à jour (32 bits signé)
_rl_hash_step = (h, s) ->
  for i = 1, #s
    h = bit.tobit(h * 33 + s\byte(i))
  h

--- Hash de l'empreinte d'un message (niveau + action + champs discriminants).
-- Les champs absents ne participent pas. Fonction pure, exportée pour les
-- tests (collision de slot).
--
-- Règle explicite (`keys` fourni et différent de RL_IDENTITY_KEYS) : parcours
-- ordonné de la liste, comme avant.
-- Règle par défaut (keys == RL_IDENTITY_KEYS, ou nil) : parcours de `fields`
-- en ignorant `action` et les champs volatils — donc tout champ inconnu est
-- une identité. `pairs` n'ayant pas d'ordre stable, le hash de chaque champ
-- est combiné par XOR (commutatif) : le résultat ne dépend pas de l'ordre et
-- aucune table intermédiaire n'est allouée sur le chemin chaud.
--
-- @tparam string level  Niveau de log
-- @tparam table  fields Champs du message
-- @tparam table|nil keys Clés discriminantes (cfg.keys ; résolues si nil)
-- @treturn number Hash 32 bits non signé
_rl_hash = (level, fields, keys) ->
  action = fields.action or level
  unless keys
    cfg = _rl_resolve_cfg level, fields
    keys = cfg and cfg.keys
  h = _rl_hash_step 0, level
  h = _rl_hash_step h, "\1"
  h = _rl_hash_step h, action
  if keys == nil or keys == RL_IDENTITY_KEYS
    for k, v in pairs fields
      if k != "action" and not RL_VOLATILE_SET[k]
        fh = _rl_hash_step 0, (RL_SEP[k] or ("\1" .. k .. "="))
        fh = _rl_hash_step fh, tostring v
        h = bit.bxor h, fh
  else
    for k in *keys
      v = fields[k]
      if v != nil
        h = _rl_hash_step h, (RL_SEP[k] or ("\1" .. k .. "="))
        h = _rl_hash_step h, tostring v
  h % 4294967296

--- Vide l'état partagé (tests uniquement).
_rl_reset = ->
  _rl_sat_warned = false
  if _rl_base
    for i = 0, RL_MMAP_WORDS - 1
      _rl_base[i] = 0
  else
    for k in pairs _rl
      _rl[k] = nil
    _rl_fb_n = 0
    _rl_fb_sat = 0

-- ── Formatage ─────────────────────────────────────────────────────

--- Retourne le timestamp Unix courant (secondes).
-- @treturn number epoch courant
now = ->
  libc.clock_gettime 0, ts   -- CLOCK_REALTIME = 0
  tonumber ts.tv_sec

--- Met en forme une ligne de log (fonction pure, testable).
-- @tparam number epoch      Timestamp Unix (secondes)
-- @tparam number pid        PID émetteur
-- @tparam string level      Niveau de log
-- @tparam table  fields     Champs clé=valeur
-- @tparam number suppressed Nombre de messages supprimés (0 = aucun)
-- @treturn string Ligne complète terminée par \n
format_line = (epoch, pid, level, fields, suppressed) ->
  parts = { "[#{epoch}]", "[#{pid}]", level }
  for k, v in pairs fields
    -- Mise en guillemets si la valeur contient des espaces
    sv = tostring v
    if sv\find " "
      table.insert parts, "#{k}=\"#{sv}\""
    else
      table.insert parts, "#{k}=#{sv}"
  table.insert parts, "suppressed=#{suppressed}" if suppressed and suppressed > 0
  table.concat(parts, " ") .. "\n"

--- Écrit une ligne hors du chemin de rate-limiting.
-- Utilisé quand le limiteur lui-même est en panne (mmap échoué, saturation) :
-- passer par write_log/check_rl risquerait une récursion dans le limiteur.
_emit_line = (level, fields) ->
  libc.clock_gettime 0, ts   -- CLOCK_REALTIME = 0
  line = format_line tonumber(ts.tv_sec), tonumber(ffi.C.getpid()), level, fields, 0
  libc.write STDOUT_FILENO, line, #line

--- Signale une saturation du limiteur (une fois par processus).
_rl_warn_saturated = ->
  return if _rl_sat_warned
  _rl_sat_warned = true
  _emit_line "WARN", {
    action: "log_rl_saturated"
    slots: RL_SLOTS
    probe_max: RL_PROBE_MAX
    detail: "aucun slot recyclable : messages journalisés sans rate-limiting"
  }

--- Indique si le limiteur partage son état entre processus.
-- @treturn boolean true si la table mmap partagée est utilisée
rl_shared = -> _rl_base != nil

--- Statistiques observables du limiteur.
-- @treturn table `{ shared, saturated, slots }` ; `saturated` compte les
-- messages journalisés sans rate-limiting faute de slot recyclable.
rl_stats = ->
  if _rl_base
    { shared: true, saturated: tonumber(_rl_base[1]), slots: RL_SLOTS }
  else
    { shared: false, saturated: _rl_fb_sat, slots: RL_SLOTS }

--- Force le repli par processus (tests uniquement).
-- @tparam boolean enable true = désactive la table partagée ; false = restaure
_rl_force_fallback = (enable) ->
  if enable
    _rl_saved_base = _rl_base unless _rl_base == nil
    _rl_base = nil
  elseif _rl_saved_base
    _rl_base = _rl_saved_base
    _rl_saved_base = nil

--- Lit un slot partagé (tests uniquement : contrôle fin des collisions).
-- @tparam number index Index de slot (0-based)
-- @treturn table|nil `{ hash, ts, expires, count }`, nil si repli actif
_rl_slot_get = (index) ->
  return nil unless _rl_base
  off = RL_HEADER_WORDS + index * RL_SLOT_WORDS
  {
    hash: tonumber(_rl_base[off])
    ts: tonumber(_rl_base[off + 1])
    expires: tonumber(_rl_base[off + 2])
    count: tonumber(_rl_base[off + 3])
  }

--- Écrit un slot partagé (tests uniquement).
-- @tparam number index   Index de slot (0-based)
-- @tparam number hash    Hash d'empreinte
-- @tparam number ts      Timestamp de dernière émission (0 = libre)
-- @tparam number expires Échéance absolue
-- @tparam number|nil count Compteur de suppressions
-- @treturn nil
_rl_slot_set = (index, hash, ts, expires, count) ->
  return nil unless _rl_base
  off = RL_HEADER_WORDS + index * RL_SLOT_WORDS
  _rl_base[off] = hash
  _rl_base[off + 1] = ts
  _rl_base[off + 2] = expires
  _rl_base[off + 3] = count or 0

check_rl = (level, fields, epoch) ->
  action_key = fields.action or level
  return 0 if _rl_never_limited fields.action
  cfg = _rl_resolve_cfg level, fields
  return 0 unless cfg

  -- write_log laisse `epoch` nil : `ts` vient d'être rempli par clock_gettime.
  -- Les tests passent une valeur explicite pour simuler le temps.
  epoch or= tonumber ts.tv_sec

  if _rl_base
    -- Le niveau et l'action complète font partie de l'empreinte : une même
    -- action émise en INFO et en WARN ne partage pas le compteur de l'autre.
    h = _rl_hash level, fields, cfg.keys
    base = _rl_base
    window = cfg.window
    slot = h % RL_SLOTS
    oldest_slot = nil
    oldest_exp = nil
    for _probe = 1, RL_PROBE_MAX
      off = RL_HEADER_WORDS + slot * RL_SLOT_WORDS
      sh = tonumber base[off]
      sts = tonumber base[off + 1]
      sexp = tonumber base[off + 2]
      -- Lecture non atomique : `{hash, ts, expires}` peut avoir été recyclé
      -- entre deux accès. On relit le hash et on exige sa stabilité ; sinon
      -- on continue le sondage — jamais de décision sur un slot instable, sous
      -- peine de supprimer une ligne qui devait être émise (ou le contraire).
      unless sh == tonumber base[off]
        slot = (slot + 1) % RL_SLOTS
        continue
      if sts == 0
        base[off] = h
        base[off + 1] = epoch
        base[off + 2] = epoch + window
        base[off + 3] = 0
        return 0
      if sh == h
        -- Horloge en marche arrière (`epoch < sts`, pas de RTC, step NTP) :
        -- l'entrée est traitée comme expirée, sinon elle resterait vivante
        -- éternellement et plus rien ne serait recyclé.
        if epoch >= sts and epoch < sexp
          base[off + 3] = tonumber(base[off + 3]) + 1
          return -1   -- supprimer
        -- Fenêtre expirée : retourner le compteur puis réinitialiser
        old_count = tonumber base[off + 3]
        base[off + 1] = epoch
        base[off + 2] = epoch + window
        base[off + 3] = 0
        return old_count
      -- Empreinte différente : recyclage sûr seulement si SA fenêtre est
      -- passée (échéance stockée dans le slot) ; sinon on la mémorise comme
      -- candidate pour la main d'horloge.
      if epoch < sts or epoch >= sexp
        base[off] = h
        base[off + 1] = epoch
        base[off + 2] = epoch + window
        base[off + 3] = 0
        return 0
      if oldest_exp == nil or sexp < oldest_exp
        oldest_exp = sexp
        oldest_slot = slot
      slot = (slot + 1) % RL_SLOTS
    -- Sondage épuisé : main d'horloge. On repart du slot de l'entrée la plus
    -- ancienne vue pendant le sondage et on balaie RL_HAND_SCAN slots à la
    -- recherche d'une entrée dont la fenêtre est passée. On ne recycle JAMAIS
    -- une entrée encore vivante : si aucune ne l'est, on journalise sans
    -- supprimer et on incrémente le compteur de saturation.
    hand = oldest_slot or (tonumber(base[0]) % RL_SLOTS)
    for _step = 1, RL_HAND_SCAN
      off = RL_HEADER_WORDS + hand * RL_SLOT_WORDS
      sh = tonumber base[off]
      sts = tonumber base[off + 1]
      sexp = tonumber base[off + 2]
      if sh == tonumber(base[off]) and sts != 0 and (epoch < sts or epoch >= sexp)
        base[off] = h
        base[off + 1] = epoch
        base[off + 2] = epoch + window
        base[off + 3] = 0
        base[0] = (hand + 1) % RL_SLOTS
        return 0
      hand = (hand + 1) % RL_SLOTS
    base[0] = hand
    base[1] = tonumber(base[1]) + 1
    _rl_warn_saturated!
    return 0   -- saturé : journaliser sans supprimer
  else
    -- Repli par processus si mmap a échoué ou pendant les tests. Plafond
    -- global : on purge d'abord les entrées expirées, et seulement si la table
    -- reste pleine on repart de zéro plutôt que de croître indéfiniment.
    fp = rl_fingerprint "#{level}|#{action_key}", fields, cfg.keys
    entry = _rl[fp]
    if entry
      if epoch >= entry.ts and epoch < entry.expires
        entry.count += 1
        return -1
      old_count = entry.count
      entry.ts = epoch
      entry.expires = epoch + cfg.window
      entry.count = 0
      return old_count
    else
      if _rl_fb_n >= RL_SLOTS
        for k, e in pairs _rl
          if epoch < e.ts or epoch >= e.expires
            _rl[k] = nil
            _rl_fb_n -= 1
        if _rl_fb_n >= RL_SLOTS
          for k in pairs _rl
            _rl[k] = nil
          _rl_fb_n = 0
          _rl_fb_sat += 1
          _rl_warn_saturated!
      _rl[fp] = { ts: epoch, expires: epoch + cfg.window, count: 0 }
      _rl_fb_n += 1
      return 0

--- Écrit une ligne de log structurée (lazy evaluation obligatoire).
-- Format : [epoch] [pid] LEVEL k1=v1 k2=v2 ...
-- @tparam string level  Niveau de log : "ERROR", "WARN", "INFO", "DEBUG", "TRACE", "ALLOW", "BLOCK"
-- @tparam function thunk Fonction () -> table de champs, appelée uniquement si niveau OK
-- @treturn nil
write_log = (level, thunk) ->
  -- Filtrer selon le niveau de log configuré (vérification rapide avant d'appeler thunk)
  if get_log_level_num(level) < CURRENT_LOG_LEVEL_NUM
    return

  -- Lazy evaluation: appeler thunk pour obtenir les fields
  fields = thunk!
  return unless fields  -- thunk peut retourner nil pour "pas de log"

  -- Apply process-scoped action prefix if set and not already present.
  if _action_prefix != "" and fields.action
    unless fields.action\sub(1, #_action_prefix) == _action_prefix
      new_fields = {}
      for k, v in pairs fields
        new_fields[k] = v
      new_fields.action = _action_prefix .. fields.action
      fields = new_fields

  libc.clock_gettime 0, ts   -- remplit ts utilisé par check_rl
  epoch = tonumber ts.tv_sec
  pid   = tonumber ffi.C.getpid()

  suppressed = check_rl level, fields
  return if suppressed == -1

  line = format_line epoch, pid, level, fields, suppressed
  if _timing_enabled
    t0 = monotonic_us!
    libc.write STDOUT_FILENO, line, #line
    libc.clock_gettime CLOCK_MONOTONIC, _timing_end
    t1 = tonumber(_timing_end.tv_sec) * 1000000 + math.floor(tonumber(_timing_end.tv_nsec) / 1000)
    _last_write_us = t1 - t0
  else
    libc.write STDOUT_FILENO, line, #line

--- Raccourcis sémantiques vers write_log avec niveaux prédéfinis (tous lazy).
-- @tparam function thunk Fonction () -> table de champs clé=valeur
-- @treturn nil
log_allow = (thunk) -> write_log "ALLOW", thunk
--- @tparam function thunk Fonction () -> table de champs clé=valeur
-- @treturn nil
log_block = (thunk) -> write_log "BLOCK", thunk
--- @tparam function thunk Fonction () -> table de champs clé=valeur
-- @treturn nil
log_info  = (thunk) -> write_log "INFO",  thunk
--- @tparam function thunk Fonction () -> table de champs clé=valeur
-- @treturn nil
log_warn  = (thunk) -> write_log "WARN",  thunk
--- @tparam function thunk Fonction () -> table de champs clé=valeur
-- @treturn nil
log_error = (thunk) -> write_log "ERROR", thunk

--- @tparam function thunk Fonction () -> table de champs clé=valeur
-- @treturn nil
log_debug = (thunk) -> write_log "DEBUG", thunk

--- @tparam function thunk Fonction () -> table de champs clé=valeur
-- @treturn nil
log_trace = (thunk) -> write_log "TRACE", thunk

-- Échec de mmap : le limiteur retombe sur une table par processus, donc le
-- partage inter-processus est perdu. On le signale une fois par processus,
-- en écrivant la ligne directement (le limiteur est justement en panne :
-- passer par write_log/check_rl risquerait une récursion).
unless _rl_base
  _emit_line "WARN", {
    action: "log_rl_mmap_failed"
    reason: _rl_fallback_reason or "unknown"
    rl_shared: 0
    arch: (jit and jit.arch) or "unknown"
  }

{ :write_log, :log_allow, :log_block, :log_info, :log_warn, :log_error, :log_debug, :log_trace, :now, :get_log_level_num, :level_enabled, :rl_fingerprint, :set_action_prefix, :RL_CONFIG, :RL_IDENTITY_KEYS, :RL_IDENTITY_SET, :RL_VOLATILE_KEYS, :RL_VOLATILE_SET, :RL_SLOTS, :RL_PROBE_MAX, :MAP_ANONYMOUS, :_map_anonymous, :check_rl, :format_line, :rl_shared, :rl_stats, :_rl_hash, :_rl_reset, :_rl_never_limited, :_rl_force_fallback, :_rl_slot_get, :_rl_slot_set, :set_timing, :get_last_write_us }
