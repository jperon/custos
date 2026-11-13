-- src/ipc.moon
-- Protocole IPC entre worker_questions et worker_responses.
-- Format A4 : 12 champs pipe-séparés, one-line, versionné.
--
-- Les modificateurs comportementaux (dnsonly, strip_aaaa, …) sont encodés
-- dans un champ bitmask générique « mods » : les modules action s'enregistrent
-- via register_modifier ; les bits sont attribués à la première utilisation
-- (tri alphabétique → déterminisme entre les deux workers).
-- Ajouter un nouveau type d'action = appeler register_modifier une fois.
-- Aucune constante MSG_XXX par type d'action.

{ :ffi, :libc } = require "ffi_defs"
config = require "config"
lowmem = require "lib.lowmem"
{ :log_warn, :log_info } = require "log"
{ :to_hex, :from_hex, :split_fields, :is_valid_timeout,
  :is_ipv4_str, :is_ipv6_str, :is_valid_mac } = require "lib.ipc_hex"

bit = require "bit"

runtime_cfg = config.runtime or {}
nft_cfg     = config.nft    or {}
ipc_cfg     = config.ipc    or {}

IPC_VERSION        = "v1"
IPC_READ_CHUNK     = 2048
IPC_MAX_LINE       = 1024
IPC_WRITE_RETRY_COUNT = 5

-- Borne par défaut de la table `pending` résolue par `lib.lowmem` (cf.
-- `ipc.pending_max`) : 20 000, ou 5 000 en mode RAM faible. Justification et
-- taille mémoire mesurée : doc/CONFIG.md § 6, docs/agents/perf.md §15.5.

EAGAIN       = 11
EWOULDBLOCK  = 11

timespec_ptr_t = ffi.typeof "timespec_t[1]"
-- Buffer timespec réutilisé pour le nanosleep de write_with_retry : alloué
-- une fois par processus au lieu d'un cdata par écriture (cf.
-- docs/agents/perf.md §22 ; même motif que nft_queue.sleep_req).
sleep_req = timespec_ptr_t!
read_buf       = ffi.new "uint8_t[?]", IPC_READ_CHUNK

-- ── Types de messages : famille + refus uniquement ──────────────────
MSG_IPV4         = 0x41   -- 'A'
MSG_IPV6         = 0x36   -- '6'
MSG_IPV4_REFUSED = 0x52   -- 'R'
MSG_IPV6_REFUSED = 0x72   -- 'r'
RESOLVER_IPV6_FLAG = 0x80

-- ── Registre dynamique des modificateurs ────────────────────────────
-- Les modules action appellent register_modifier au chargement.
-- _finalize! trie les noms et attribue les bits (idem dans les deux workers
-- car ils chargent les mêmes modules depuis la même config filtre).
_registered = {}
_mod_bits   = {}
_finalized  = false

_finalize = ->
  return if _finalized
  table.sort _registered
  for i, name in ipairs _registered
    _mod_bits[name] = bit.lshift 1, (i - 1)
  _finalized = true

--- Enregistre un modificateur IPC.  Appelé par les modules action au chargement.
-- @tparam string name  Nom du modificateur (ex: "dnsonly", "strip_aaaa")
register_modifier = (name) ->
  for existing in *_registered
    return if existing == name
  _registered[#_registered + 1] = name
  _finalized = false  -- forcer re-finalize si de nouveaux modules chargés

--- Retourne le bit assigné à un modificateur (finalise si nécessaire).
modifier_bit = (name) ->
  _finalize! unless _finalized
  _mod_bits[name] or 0

--- Encode une table {name → bool} en entier bitmask.
encode_modifiers = (mods) ->
  return 0 unless mods
  _finalize! unless _finalized
  result = 0
  for name, val in pairs mods
    b = _mod_bits[name]
    result = bit.bor result, b if b and val
  result

--- Decode un entier bitmask en table {name → bool}.
decode_modifiers = (bits) ->
  _finalize! unless _finalized
  result = {}
  for name, b in pairs _mod_bits
    result[name] = bit.band(bits, b) != 0
  result

-- ── Helpers ──────────────────────────────────────────────────────────
-- Encodage hexadécimal et découpage des champs : lib.ipc_hex (partagé avec
-- worker_nft et nft_queue).

{ :mac2s } = require "ipparse.l2.ethernet"
{ :ip2s }  = require "ipparse.l3.ip"

-- Mémo MAC brute → texte : 6 conversions hexadécimales par message, alors
-- qu'un LAN n'a qu'une poignée de MAC. Borné (purge en bloc), clé = les
-- 6 octets bruts (chaîne internée par LuaJIT, donc identité stable).
MAC_STR_MAX = 64
_mac_str_cache = {}
_mac_str_n     = 0

--- Convertit 6 octets bruts en "aa:bb:cc:dd:ee:ff", mémoïsé.
-- @tparam string|nil mac_raw Octets bruts
-- @treturn string Texte (MAC nulle si l'entrée est invalide)
mac_raw_to_str = (mac_raw) ->
  return "00:00:00:00:00:00" unless mac_raw and #mac_raw == 6
  hit = _mac_str_cache[mac_raw]
  return hit if hit
  s = mac2s mac_raw
  if _mac_str_n >= MAC_STR_MAX
    _mac_str_cache = {}
    _mac_str_n     = 0
  _mac_str_cache[mac_raw] = s
  _mac_str_n += 1
  s

-- Tables d'encodage hexadécimal des petits entiers (msg_type < 128, bits de
-- modificateurs < 256) : évite deux `string.format` par message.
_HEX2 = {}
_HEX1 = {}
for i = 0, 255
  _HEX2[i] = string.format "%02x", i
  _HEX1[i] = string.format "%x", i

ip_raw_to_str = (ip_raw) ->
  return nil unless ip_raw and (#ip_raw == 4 or #ip_raw == 16)
  ip2s ip_raw

msg_type_for = (ipv4, refused) ->
  if ipv4
    return MSG_IPV4_REFUSED if refused
    return MSG_IPV4
  return MSG_IPV6_REFUSED if refused
  MSG_IPV6

write_with_retry = (pipe_wfd, msg) ->
  for i = 1, IPC_WRITE_RETRY_COUNT
    n = libc.write pipe_wfd, msg, #msg
    return true if n == #msg
    errno_p = libc.__errno_location!
    errno = if errno_p then errno_p[0] else 0
    if errno != EAGAIN and errno != EWOULDBLOCK
      log_warn -> { action: "ipc_write_syscall_failed", fd: pipe_wfd, errno: errno, attempt: i }
      return false
    sleep_req[0].tv_sec = 0
    sleep_req[0].tv_nsec = 20000000
    libc.nanosleep sleep_req, nil
  errno_p = libc.__errno_location!
  errno = if errno_p then errno_p[0] else 0
  log_warn -> { action: "ipc_write_failed_exhausted", fd: pipe_wfd, errno: errno, attempts: IPC_WRITE_RETRY_COUNT }
  false

-- Destinataires (fds) dont le tube était plein (EAGAIN) au dernier essai. Tant
-- qu'un fd y figure, on ne lui consacre plus qu'UNE écriture non bloquante par
-- message : un tube durablement plein — worker réponses arrêté, ou file NFQUEUE
-- inactive — ne peut plus coûter IPC_WRITE_RETRY_COUNT × 20 ms de nanosleep PAR
-- QUESTION (cf. docs/agents/perf.md §12 : 5 × 20 ms par question, puis
-- NF_DROP de chaque question → blocage définitif du service). L'état est effacé
-- dès qu'une écriture réussit.
_saturated = {}

--- Tente une écriture unique, sans jamais dormir.
-- Utilisé pour un destinataire déjà saturé : sur EAGAIN on ne logue rien (le
-- WARN de saturation a déjà été émis), sur une autre errno on logue.
-- @tparam number pipe_wfd fd d'écriture
-- @tparam string msg      Message encodé
-- @treturn boolean true si toute la ligne a été écrite
write_once = (pipe_wfd, msg) ->
  n = libc.write pipe_wfd, msg, #msg
  return true if n == #msg
  errno_p = libc.__errno_location!
  errno = if errno_p then errno_p[0] else 0
  if errno != EAGAIN and errno != EWOULDBLOCK
    log_warn -> { action: "ipc_write_syscall_failed", fd: pipe_wfd, errno: errno, attempt: 1 }
  false

--- Écrit un message IPC sur un fd, ou sur CHAQUE fd d'une liste (fan-out).
-- Avec plusieurs workers réponses (plage `nfqueue.responses`), chaque worker
-- reçoit une copie de CHAQUE transaction : l'appariement question/réponse ne
-- dépend alors pas de l'affinité de hachage du noyau (la réponse peut être
-- livrée à n'importe quelle file de la plage). Écriture ≤ PIPE_BUF donc
-- atomique par destinataire.
-- Contrat de retour : true dès qu'AU MOINS UN destinataire a reçu la ligne.
-- Un tube plein ne doit pas jeter la question (les autres workers l'ont reçue,
-- et la réponse peut arriver chez eux) ; seul l'échec de TOUS est un échec.
-- Un destinataire saturé (EAGAIN) est marqué : ses messages suivants ne coûtent
-- plus qu'une écriture non bloquante, sans nanosleep, jusqu'au premier succès.
-- @tparam number|table pipe_wfd fd unique, ou liste de fds
-- @tparam string msg Message encodé
-- @treturn boolean true si au moins un destinataire a reçu la ligne
write_with_retry_all = (pipe_wfd, msg) ->
  return write_with_retry pipe_wfd, msg unless type(pipe_wfd) == "table"
  delivered = false
  for fd in *pipe_wfd
    ok = false
    if _saturated[fd]
      ok = write_once fd, msg
      if ok
        _saturated[fd] = nil
        log_info -> { action: "ipc_write_resumed", fd: fd }
    elseif write_with_retry fd, msg
      ok = true
    else
      _saturated[fd] = true
      log_warn -> { action: "ipc_write_saturated", ipc_fd: fd }
    delivered = true if ok
  delivered

--- Encode un message IPC.
-- @tparam number      txid          Transaction DNS
-- @tparam string      ip_raw        IP source (4 ou 16 octets)
-- @tparam number      src_port      Port source
-- @tparam string      mac_raw       MAC source (6 octets)
-- @tparam string      resolver_ip_raw IP résolveur
-- @tparam boolean     refused       true si réponse REFUSED
-- @tparam string      reason        Raison (tronquée à 63 chars)
-- @tparam number|nil  benchmark_ms  Horodatage d'entrée question (base q_to_response_ms)
-- @tparam string|nil  rule_id       Identifiant de règle
-- @tparam string|nil  timeout       Timeout nft (ex: "2m")
-- @tparam table|nil   modifiers     Table {nom → bool} des modificateurs actifs
-- @tparam table|nil   response_rule_ids Liste ordonnée des rule_id à appliquer côté response
-- @tparam number|nil  question_proc_ms Durée du traitement interne question (ms)
-- @treturn string|nil Ligne IPC prête à écrire, ou nil si invalide
encode_msg = (txid, ip_raw, src_port, mac_raw, resolver_ip_raw, refused, reason, benchmark_ms, rule_id, timeout, modifiers, response_rule_ids=nil, question_proc_ms=nil) ->
  return nil unless ip_raw and resolver_ip_raw
  return nil unless (#ip_raw == 4 or #ip_raw == 16)
  return nil unless (#resolver_ip_raw == 4 or #resolver_ip_raw == 16)

  ipv4     = #ip_raw == 4
  msg_type = msg_type_for ipv4, not not refused
  msg_type = bit.bor msg_type, RESOLVER_IPV6_FLAG if #resolver_ip_raw == 16

  client_ip   = ip_raw_to_str ip_raw
  resolver_ip = ip_raw_to_str resolver_ip_raw
  return nil unless client_ip and resolver_ip

  timeout = timeout or nft_cfg.ip_timeout or "2m"
  timeout = tostring timeout
  return nil unless is_valid_timeout timeout

  reason  = tostring(reason  or "")
  rule_id = tostring(rule_id or "")
  reason  = reason\sub(1, 63)   if #reason  > 63
  -- rule_id : aligner sur la limite filter.rule_id.sanitize_id (128 chars)
  -- + le préfixe "r_" = 130 chars max. La limite précédente (63) tronquait
  -- les rule_ids longs et désynchronisait les noms de sets nft côté worker.
  rule_id = rule_id\sub(1, 130) if #rule_id > 130

  bench = tonumber(benchmark_ms) or 0
  bench = 0 if bench < 0
  bench = math.floor bench

  qproc = tonumber(question_proc_ms) or 0
  qproc = 0 if qproc < 0
  qproc = math.floor qproc

  mods_bits = encode_modifiers modifiers
  -- response_ids : le tableau n'est construit que s'il y a des ids (sinon
  -- le champ vaut "" comme avant, sans allocation).
  response_ids_hex = ""
  if type(response_rule_ids) == "table"
    response_ids = {}
    for _, rid in ipairs response_rule_ids
      break if #response_ids >= 8
      continue unless rid and rid != ""
      response_ids[#response_ids + 1] = tostring(rid)
    if #response_ids > 0
      response_ids_hex = to_hex table.concat response_ids, ","
  -- Concaténation directe (14 champs + "\n") : la forme à table.concat
  -- allouait un tableau de 14 slots + 2 strings par question (cf.
  -- docs/agents/perf.md §22).
  line = IPC_VERSION .. "|" .. (_HEX2[msg_type] or string.format("%02x", msg_type)) ..
    "|" .. tostring(tonumber(txid) or 0) ..
    "|" .. client_ip ..
    "|" .. tostring(tonumber(src_port) or 0) ..
    "|" .. resolver_ip ..
    "|" .. mac_raw_to_str(mac_raw) ..
    "|" .. to_hex(reason) ..
    "|" .. to_hex(rule_id) ..
    "|" .. timeout ..
    "|" .. (bench == 0 and "0" or tostring(bench)) ..
    "|" .. (_HEX1[mods_bits] or string.format("%x", mods_bits)) ..
    "|" .. response_ids_hex ..
    "|" .. (qproc == 0 and "0" or tostring(qproc)) .. "\n"

  return nil if #line > IPC_MAX_LINE
  line

write_msg = (pipe_wfd, txid, ip_raw, src_port, mac_raw, resolver_ip_raw, reason, benchmark_ms, rule_id, timeout, modifiers, response_rule_ids=nil, question_proc_ms=nil) ->
  msg = encode_msg txid, ip_raw, src_port, mac_raw, resolver_ip_raw, false, reason, benchmark_ms, rule_id, timeout, modifiers, response_rule_ids, question_proc_ms
  return false unless msg
  write_with_retry_all pipe_wfd, msg

write_refused_msg = (pipe_wfd, txid, ip_raw, src_port, mac_raw, resolver_ip_raw, reason, benchmark_ms, rule_id, timeout, modifiers, response_rule_ids=nil, question_proc_ms=nil) ->
  msg = encode_msg txid, ip_raw, src_port, mac_raw, resolver_ip_raw, true, reason, benchmark_ms, rule_id, timeout, modifiers, response_rule_ids, question_proc_ms
  return false unless msg
  write_with_retry_all pipe_wfd, msg

decode_msg = (raw) ->
  return nil, "empty" unless raw and #raw > 0
  -- Le \n final est déjà retiré par `drain_lines` (chemin chaud) : ne payer le
  -- motif que si l'appelant passe une ligne brute terminée par un retour.
  line = if raw\byte(#raw) == 10 then (raw\gsub "\n+$", "") else raw
  parts = split_fields line
  return nil, "field_count" unless #parts >= 11

  version = parts[1]
  return nil, "version" unless version == IPC_VERSION

  msg_type_full = tonumber parts[2], 16
  return nil, "msg_type" unless msg_type_full
  msg_type      = bit.band msg_type_full, 0x7F
  resolver_ipv6 = bit.band(msg_type_full, RESOLVER_IPV6_FLAG) != 0

  txid          = tonumber parts[3]
  src_port      = tonumber parts[5]
  benchmark_num = tonumber parts[11]
  return nil, "txid"     unless txid     and txid     >= 0 and txid     <= 65535
  return nil, "src_port" unless src_port and src_port >= 0 and src_port <= 65535
  benchmark_num = 0 unless benchmark_num and benchmark_num >= 0

  ipv4    = (msg_type == MSG_IPV4 or msg_type == MSG_IPV4_REFUSED)
  return nil, "family" unless ipv4 or msg_type == MSG_IPV6 or msg_type == MSG_IPV6_REFUSED
  refused = (msg_type == MSG_IPV4_REFUSED or msg_type == MSG_IPV6_REFUSED)

  ip_str          = parts[4]
  resolver_ip_str = parts[6]
  return nil, "ip_client"   unless (ipv4 and is_ipv4_str(ip_str))   or ((not ipv4) and is_ipv6_str(ip_str))
  return nil, "ip_resolver" unless (resolver_ipv6 and is_ipv6_str(resolver_ip_str)) or
                                    ((not resolver_ipv6) and is_ipv4_str(resolver_ip_str))

  mac_str = parts[7]\lower!
  return nil, "mac" unless is_valid_mac mac_str

  reason,  reason_err  = from_hex parts[8]
  return nil, "reason_#{reason_err}"  if reason_err
  rule_id, rule_err    = from_hex parts[9]
  return nil, "rule_id_#{rule_err}"   if rule_err

  timeout = parts[10]
  return nil, "timeout" unless is_valid_timeout timeout

  benchmark_ms = if benchmark_num > 0 then benchmark_num else nil

  -- Champ question_proc_ms optionnel (rétrocompatibilité messages < 14 champs)
  question_proc_num = tonumber parts[14]
  question_proc_ms = if question_proc_num and question_proc_num > 0 then question_proc_num else nil

  -- Champ mods optionnel (rétrocompatibilité messages 11 champs)
  mods_hex  = parts[12] or "0"
  mods_bits = tonumber(mods_hex, 16) or 0
  modifiers = decode_modifiers mods_bits

  response_rule_ids_hex = parts[13] or ""
  response_rule_ids_csv, ids_err = from_hex response_rule_ids_hex
  return nil, "response_rule_ids_#{ids_err}" if ids_err
  response_rule_ids = {}
  if response_rule_ids_csv and response_rule_ids_csv != ""
    for rid in response_rule_ids_csv\gmatch "[^,]+"
      response_rule_ids[#response_rule_ids + 1] = rid

  {
    :txid
    :ip_str
    :src_port
    :resolver_ip_str
    :msg_type
    :mac_str
    :ipv4
    :refused
    :reason
    :benchmark_ms
    :question_proc_ms
    :rule_id
    :timeout
    :modifiers
    :response_rule_ids
  }, nil

pending     = {}
read_states = {}

-- ── Borne de la table `pending` ────────────────────────────────────────
-- Liste doublement chaînée d'insertion : la tête est l'entrée à l'activité la
-- plus ancienne (insertion ou rafraîchissement de `expire`), la queue la plus
-- récente. `consume`, la purge et l'expiration démaillent le nœud en O(1) :
-- aucun emplacement fantôme ne s'accumule tant que la table reste sous sa
-- borne. `_pending_size` évite un parcours complet à chaque insertion.
_pending_head      = nil
_pending_tail      = nil
_pending_size      = 0
_pending_evictions = 0

_configured_pending_max = tonumber ipc_cfg.pending_max
_pending_max = lowmem.resolve_pending_max _configured_pending_max,
  lowmem.detect runtime_cfg

make_key = (txid, ip_str, src_port, resolver_ip_str) ->
  string.format "%04x:%s:%d:%s", txid, ip_str, src_port, resolver_ip_str

-- Champs de verdict/metadonnées comparés pour détecter une divergence entre
-- deux questions partageant la même clé `pending`.
_pending_meta_fields = { "refused", "rule_id", "reason", "timeout" }

-- Raison synthétique d'une entrée refusée par fail-closed : deux questions
-- autorisées par des règles différentes ne permettent pas de prouver qu'un
-- choix de métadonnées n'élargit pas l'accès (cf. overwrite_pending).
PENDING_CONFLICT_REASON = "ipc_pending_conflict"

--- Compare deux tables de modificateurs décodés (mêmes clés attendues).
-- @tparam table|nil a
-- @tparam table|nil b
-- @treturn boolean true si les deux tables portent les mêmes valeurs
_pending_modifiers_equal = (a, b) ->
  a or= {}
  b or= {}
  for k, v in pairs a
    return false if b[k] != v
  for k, v in pairs b
    return false if a[k] != v
  true

--- Compare deux listes de `response_rule_ids` (ordre significatif).
-- @tparam table|nil a
-- @tparam table|nil b
-- @treturn boolean true si les deux listes sont identiques
_pending_ids_equal = (a, b) ->
  a or= {}
  b or= {}
  return false if #a != #b
  for i = 1, #a
    return false if a[i] != b[i]
  true

--- Indique si deux questions réutilisant la même clé portent un verdict différent.
-- Comparaison STRICTE des champs de métadonnées transmis par l'IPC, y compris
-- `modifiers` et `response_rule_ids` (ils pilotent les hooks on_response et
-- l'injection nft, cf. src/worker_responses.moon:599-638). qname et qtype n'y
-- figurent pas (format A4) : une divergence de CONTENU de question avec un
-- verdict identique reste donc indétectable ici.
-- @tparam table a Entrée `pending` existante
-- @tparam table b Message IPC entrant
-- @treturn boolean true si au moins un champ de métadonnées diffère
pending_meta_diverges = (a, b) ->
  for name in *_pending_meta_fields
    return true if a[name] != b[name]
  return true unless _pending_modifiers_equal a.modifiers, b.modifiers
  return true unless _pending_ids_equal a.response_rule_ids, b.response_rule_ids
  false

--- Adopte les champs de verdict d'une question refusée sur une entrée autorisée.
-- Seuls les champs cohérents avec le verdict refusé sont copiés ; les jalons
-- `benchmark_ms`/`question_proc_ms` de la première question sont conservés
-- (base de `q_to_response_ms`, sans effet sur l'accès).
-- @tparam table entry Entrée `pending` existante (mutée)
-- @tparam table msg   Message IPC refusé entrant
-- @treturn nil
_adopt_refused = (entry, msg) ->
  entry.refused            = true
  entry.rule_id            = msg.rule_id
  entry.reason             = msg.reason
  entry.timeout            = msg.timeout
  entry.modifiers          = msg.modifiers
  entry.response_rule_ids  = msg.response_rule_ids or {}
  nil

--- Résout une divergence de métadonnées vers le verdict le plus restrictif.
-- @tparam table entry Entrée `pending` existante (mutée si un refus est adopté)
-- @tparam table msg   Message IPC entrant
-- @treturn string Résolution : "kept_refused", "adopted_refused" ou
--                  "kept_allowed_conflict"
_most_restrictive = (entry, msg) ->
  if entry.refused
    -- Première question déjà refusée : aucun élargissement possible.
    "kept_refused"
  elseif msg.refused
    -- Fail-closed : la question refusée impose son verdict à l'entrée.
    _adopt_refused entry, msg
    "adopted_refused"
  else
    -- Deux autorisations par des règles différentes : garder l'une ou l'autre
    -- appliquerait ses hooks on_response et son injection nft à la réponse de
    -- l'autre (src/worker_responses.moon:599-638 : response_hooks, inject),
    -- sans preuve que ce ne soit pas plus permissif (ex. règle « dnsonly » ou
    -- strip d'une part, allow normale de l'autre). Aucun choix prouvable →
    -- marquer l'entrée refusée (fail-closed).
    entry.refused = true
    entry.reason  = PENDING_CONFLICT_REASON
    "kept_allowed_conflict"

--- Démaille un nœud de la liste d'insertion (O(1)).
-- @tparam table node Nœud {key, entry, prev, next}
-- @treturn nil
_unlink_pending_node = (node) ->
  prev, nxt = node.prev, node.next
  if prev then prev.next = nxt else _pending_head = nxt
  if nxt  then nxt.prev = prev else _pending_tail = prev
  node.prev = nil
  node.next = nil

--- Ajoute une entrée en queue de liste (plus récente).
-- @tparam string key   Clé `pending`
-- @tparam table  entry Entrée `pending`
-- @treturn table Nœud créé
_append_pending_node = (key, entry) ->
  node = { key: key, entry: entry, prev: _pending_tail, next: nil }
  if _pending_tail then _pending_tail.next = node else _pending_head = node
  _pending_tail = node
  entry._pending_node = node
  node

--- Déplace un nœud en queue (rafraîchissement de l'expiration).
-- @tparam table node Nœud existant
-- @treturn nil
_move_pending_node_to_tail = (node) ->
  return if _pending_tail == node
  _unlink_pending_node node
  node.prev = _pending_tail
  node.next = nil
  if _pending_tail then _pending_tail.next = node else _pending_head = node
  _pending_tail = node

--- Retire une entrée `pending` (consommation, purge ou expiration).
-- @tparam string key Clé `pending`
-- @treturn boolean true si une entrée a été retirée
_remove_pending = (key) ->
  entry = pending[key]
  return false unless entry
  pending[key] = nil
  node = entry._pending_node
  if node
    _unlink_pending_node node
    entry._pending_node = nil
  _pending_size -= 1
  true

--- Évince les entrées les plus anciennes jusqu'à respecter `ipc.pending_max`.
-- O(1) par éviction (tête de liste), sans tri. Un WARN rate-limité
-- (`pending_evicted`) est émis seulement si au moins une entrée a été évincée ;
-- la réponse dont la question a été évincée suit le chemin d'une question
-- expirée : `get_pending_entry` renvoie nil puis `worker_responses` jette la
-- réponse comme orpheline (`NF_DROP`, `response_orphan_dropped`).
-- @treturn nil
_enforce_pending_max = ->
  evicted = 0
  while _pending_size > _pending_max
    node = _pending_head
    break unless node
    pending[node.key] = nil
    node.entry._pending_node = nil
    _unlink_pending_node node
    _pending_size -= 1
    _pending_evictions += 1
    evicted += 1
  if evicted > 0
    log_warn -> {
      action: "pending_evicted"
      evicted: evicted
      entries: _pending_size
      pending_max: _pending_max
    }
  nil

--- Gère la réutilisation d'une clé `pending` déjà présente.
-- Cas identique (retransmission UDP) : first-wins, seul `expire` est rafraîchi.
-- Cas divergent : verdict le plus restrictif (fail-closed, cf. ci-dessus) —
-- une réponse n'est jamais relayée avec le `refused`/`rule_id`/`reason` d'une
-- AUTRE question moins restrictive. Motif du first-wins sur le cas identique :
-- la retransmission est la cause dominante d'une collision de clé, et conserver
-- l'entrée d'origine préserve le jalon `benchmark_ms` (base de
-- `q_to_response_ms`).
-- @tparam string key   Clé `pending` réutilisée
-- @tparam table  entry Entrée `pending` existante (mutée : expire, verdict)
-- @tparam table  msg   Message IPC entrant
-- @tparam function now_fn () -> epoch
-- @treturn nil
overwrite_pending = (key, entry, msg, now_fn) ->
  entry.expire = now_fn! + (ipc_cfg.pending_ttl or 5)
  -- Rafraîchissement = activité récente : l'entrée repasse en queue de liste
  -- d'éviction (elle ne sera plus la première victime d'une rafale).
  _move_pending_node_to_tail entry._pending_node if entry._pending_node
  unless pending_meta_diverges entry, msg
    log_info -> {
      action: "ipc_pending_overwrite"
      key: key
      txid: string.format "0x%04x", msg.txid
      client_ip: msg.ip_str
      client_port: msg.src_port
      resolver_ip: msg.resolver_ip_str
      refused: entry.refused and 1 or 0
    }
    return nil
  resolution = _most_restrictive entry, msg
  log_warn -> {
    action: "ipc_pending_overwrite_divergent"
    key: key
    txid: string.format "0x%04x", msg.txid
    client_ip: msg.ip_str
    client_port: msg.src_port
    resolver_ip: msg.resolver_ip_str
    refused_kept: entry.refused and 1 or 0
    refused_new: msg.refused and 1 or 0
    rule_kept: entry.rule_id or ""
    rule_new: msg.rule_id or ""
    resolution: resolution
  }
  nil

set_pending = (msg, now_fn) ->
  key = make_key msg.txid, msg.ip_str, msg.src_port, msg.resolver_ip_str
  previous = pending[key]
  -- Chemin nominal (aucune collision) : une seule horloge, une seule entrée.
  return overwrite_pending key, previous, msg, now_fn if previous
  entry = {
    expire:       now_fn! + (ipc_cfg.pending_ttl or 5)
    refused:      msg.refused
    modifiers:    msg.modifiers
    reason:       msg.reason
    benchmark_ms: msg.benchmark_ms
    question_proc_ms: msg.question_proc_ms
    rule_id:      msg.rule_id
    timeout:      msg.timeout
    response_rule_ids: msg.response_rule_ids or {}
  }
  pending[key] = entry
  _append_pending_node key, entry
  _pending_size += 1
  _enforce_pending_max!
  entry

drain_lines = (pipe_rfd, buf, now_fn, on_msg) ->
  absorbed = 0
  while true
    nl = buf\find "\n", 1, true
    break unless nl
    line = buf\sub 1, nl - 1
    buf  = buf\sub nl + 1
    continue if #line == 0
    msg, err = decode_msg line
    if msg
      set_pending msg, now_fn
      absorbed += 1
      on_msg msg if on_msg
    else
      log_warn -> { action: "ipc_invalid_message", fd: pipe_rfd, reason: err or "decode_failed", raw: line\sub(1, 180) }
  buf, absorbed

drain_pipe = (pipe_rfd, now_fn, on_msg) ->
  state    = read_states[pipe_rfd] or ""
  absorbed = 0
  while true
    n = libc.read pipe_rfd, read_buf, IPC_READ_CHUNK
    if n == 0
      log_warn -> { action: "ipc_pipe_eof", fd: pipe_rfd }
      break
    if n < 0
      errno_p = libc.__errno_location!
      errno = if errno_p then errno_p[0] else 0
      break if errno == EAGAIN or errno == EWOULDBLOCK
      log_warn -> { action: "ipc_read_failed", fd: pipe_rfd, errno: errno }
      break
    state ..= ffi.string read_buf, n
    if #state > IPC_MAX_LINE * 4
      log_warn -> { action: "ipc_buffer_oversize", fd: pipe_rfd, size: #state }
      state = ""
    state, added = drain_lines pipe_rfd, state, now_fn, on_msg
    absorbed += added
    break if n < IPC_READ_CHUNK
  read_states[pipe_rfd] = state
  absorbed

is_pending = (txid, ip_str, src_port, resolver_ip_str, now_fn) ->
  key   = make_key txid, ip_str, src_port, resolver_ip_str
  entry = pending[key]
  return false unless entry
  if now_fn! > entry.expire
    _remove_pending key
    return false
  true

get_pending_entry = (txid, ip_str, src_port, resolver_ip_str, now_fn) ->
  key   = make_key txid, ip_str, src_port, resolver_ip_str
  entry = pending[key]
  return nil unless entry
  if now_fn! > entry.expire
    _remove_pending key
    return nil
  entry

consume = (txid, ip_str, src_port, resolver_ip_str) ->
  _remove_pending make_key txid, ip_str, src_port, resolver_ip_str

--- Purge les entrées `pending` expirées jamais relues (question sans réponse :
-- paquet perdu, upstream muet, client qui abandonne). Sans cet appel
-- périodique, `is_pending`/`get_pending_entry` ne purgent qu'en lecture et une
-- entrée jamais relue reste en mémoire indéfiniment (hot-path le plus
-- sollicité du système). À appeler périodiquement (cf. worker_responses.moon,
-- même cadence que tcp_state.purge!/purge_mac_clients).
-- @tparam function now_fn () -> epoch
purge_pending = (now_fn) ->
  now = now_fn!
  for key, entry in pairs pending
    _remove_pending key if now > entry.expire

--- État de la table `pending` (diagnostic/tests).
-- @treturn table { size, evicted, pending_max }
pending_stats = ->
  { size: _pending_size, evicted: _pending_evictions, pending_max: _pending_max }

{
  :encode_msg
  :decode_msg
  :write_msg
  :write_refused_msg
  :register_modifier
  :modifier_bit
  :encode_modifiers
  :decode_modifiers
  :drain_pipe
  :set_pending
  :is_pending
  :get_pending_entry
  :consume
  :purge_pending
  :pending_stats
  :MSG_IPV4
  :MSG_IPV6
  :MSG_IPV4_REFUSED
  :MSG_IPV6_REFUSED
  :make_key
}
