{ :ffi, :libc } = require "ffi_defs"
{ :log_warn } = require "log"
config = require "config"
{ :to_hex, :is_valid_timeout } = require "lib.ipc_hex"

nft_cfg = config.nft or {}
FAMILY = nft_cfg.family or "bridge"
FAMILY6 = nft_cfg.family6 or "bridge"
TABLE = nft_cfg.table or "dns-filter-bridge"
IP_TIMEOUT = nft_cfg.ip_timeout or "2m"
ACK_TIMEOUT_MS  = nft_cfg.ack_timeout_ms or 150
WAIT_POLL_MS    = 5   -- intervalle de poll dans wait_ack pour permettre le drain intercalé

-- Format d'ACK : un enregistrement de taille FIXE, écrit en un seul write
-- (≤ PIPE_BUF, donc atomique) et portant le plus grand `seq` appliqué par
-- worker_nft pour ce worker. Un uint64 natif suffit : les deux extrémités
-- vivent sur la même machine (même ordre d'octets).
ACK_SIZE = 8
CLOCK_MONOTONIC = 1

PIPE_BUF_SAFE = 512
-- Borne d'une écriture atomique sur un pipe Linux (PIPE_BUF) : les producteurs
-- nft écrivent tous dans le même pipe, une tranche écrite en un seul write()
-- de ≤ PIPE_BUF_ATOMIC octets ne peut donc pas être entrelacée avec celle d'un
-- autre producteur. Au-delà, le noyau pourrait couper l'écriture.
PIPE_BUF_ATOMIC = 4096
IPC_WRITE_RETRY_COUNT = 3
EAGAIN = 11
EWOULDBLOCK = 11
POLLIN = 1

LINE_VERSION = "v1"

pipe_wfd = nil
ack_rfd = nil
worker_idx = nil
seq = 0
last_enqueued_seq = nil

sleep_req = ffi.new "timespec_t[1]"
poll_fds  = ffi.new "struct pollfd[1]"
-- Accumulateur de lecture d'un ACK : un enregistrement peut arriver en
-- plusieurs morceaux (lecture partielle), il n'est interprété que complet.
ack_rec   = ffi.new "uint8_t[?]", ACK_SIZE
ack_val   = ffi.new "uint64_t[1]"
ack_tmp   = ffi.new "uint64_t[1]"
drain_buf = ffi.new "uint8_t[64]"

-- Plus grand seq acquitté observé depuis le démarrage du processus.
-- Permet à wait_ack de ne pas RE-attendre un ACK déjà consommé : sans cela, un
-- ACK purgé par drain_ack! avant le wait_ack du lot (cas d'un lot dont la
-- dernière insertion précède une réponse qui draine) faisait expirer le budget
-- de 150 ms alors que worker_nft avait bien appliqué les insertions — mesuré
-- comme `response_nft_ack_timeout` et 150 ms d'attente par lot (cf.
-- docs/agents/perf.md §7.2).
last_acked_seq = 0

-- ── Tampon d'écriture côté producteur ───────────────────────────────
-- Les lignes d'un même lot sont accumulées puis écrites en un seul write() par
-- tranche ≤ PIPE_BUF_ATOMIC (4096 o) : une réponse DNS à N enregistrements ne
-- coûte plus N appels système mais un seul (cf. docs/agents/perf.md §16.5,
-- piste 4). Le tampon est vidé (flush) par get_last_seq, wait_ack et
-- send_barrier — et par un flush explicite de fin de paquet dans worker_sip
-- (insertions fire-and-forget). Attendre l'ACK d'une ligne encore tamponnée
-- serait un interblocage : le flush précède toujours l'attente.
pending_lines = {}   -- lignes IPC en attente, dans l'ordre du lot
pending_seqs  = {}   -- seq de chaque ligne (parallèle à pending_lines)
pending_bytes = 0    -- octets déjà accumulés dans pending_lines

--- Met à jour last_acked_seq avec les enregistrements complets d'un bloc lu.
-- worker_nft écrit chaque ACK en un seul write de ACK_SIZE octets (atomique) :
-- un bloc de taille multiple de ACK_SIZE ne contient que des enregistrements
-- complets. Un fragment partiel est ignoré (comme avant : il était jeté).
-- @tparam cdata  buf Bloc lu (uint8_t)
-- @tparam number n   Nombre d'octets lus
-- @treturn nil
_record_acks = (buf, n) ->
  return unless n and n >= ACK_SIZE and (n % ACK_SIZE) == 0
  i = 0
  while i + ACK_SIZE <= n
    ffi.copy ack_tmp, buf + i, ACK_SIZE
    v = tonumber ack_tmp[0]
    last_acked_seq = v if v > last_acked_seq
    i += ACK_SIZE
  nil

--- Plus grand seq acquitté observé par ce producteur (tests / diagnostic).
-- @treturn number
get_last_acked = -> last_acked_seq


sanitize_timeout = (timeout) ->
  t = if timeout == nil then "" else tostring timeout
  if is_valid_timeout t
    return t
  fallback = IP_TIMEOUT
  if is_valid_timeout fallback
    log_warn -> { action: "nft_queue_timeout_invalid_fallback", timeout: t, fallback: fallback }
    return fallback
  log_warn -> { action: "nft_queue_timeout_invalid_default", timeout: t }
  "2m"

sleep_ms = (ms) ->
  sleep_req[0].tv_sec = math.floor ms / 1000
  sleep_req[0].tv_nsec = (ms % 1000) * 1000000
  libc.nanosleep sleep_req, nil

-- Millisecondes monotones depuis le démarrage (budget global de wait_ack).
monotonic_ms = ->
  libc.clock_gettime CLOCK_MONOTONIC, sleep_req
  tonumber(sleep_req[0].tv_sec) * 1000 + math.floor(tonumber(sleep_req[0].tv_nsec) / 1000000)

-- Décode l'enregistrement ACK complet accumulé dans `ack_rec`.
ack_rec_seq = ->
  ffi.copy ack_val, ack_rec, ACK_SIZE
  tonumber ack_val[0]

set_wfd = (wfd) ->
  pipe_wfd = wfd

set_ack_rfd = (rfd, idx) ->
  ack_rfd    = rfd
  worker_idx = idx

write_data = (data) ->
  return false unless pipe_wfd
  len = #data
  for _ = 1, IPC_WRITE_RETRY_COUNT
    n = libc.write pipe_wfd, data, len
    return true if n == len
    errno_p = libc.__errno_location!
    errno = if errno_p then errno_p[0] else 0
    if errno != EAGAIN and errno != EWOULDBLOCK
      log_warn -> { action: "nft_queue_write_failed", fd: pipe_wfd, errno: errno }
      return false
    sleep_ms 10
  log_warn -> { action: "nft_queue_write_exhausted", fd: pipe_wfd }
  false

write_line = (line) ->
  return false unless pipe_wfd
  return false if #line > PIPE_BUF_SAFE
  write_data line

--- Écrit le tampon du lot en tranches atomiques (≤ PIPE_BUF_ATOMIC octets).
-- Un lot de N lignes = un seul write() tant que sa taille tient dans PIPE_BUF ;
-- au-delà, une tranche par 4096 octets (jamais plus), pour que l'écriture reste
-- atomique vis-à-vis des autres producteurs du même pipe.
-- Sur échec d'une tranche, les lignes non écrites restantes sont abandonnées
-- (log `nft_queue_flush_failed`) et le seq rendu par get_last_seq reste celui
-- de la dernière ligne RÉELLEMENT écrite : wait_ack n'attend jamais l'ACK
-- d'une ligne absente du pipe.
-- @treturn boolean true si toutes les lignes du tampon ont été écrites
flush = ->
  n = #pending_lines
  return true if n == 0
  ok = true
  i = 1
  while i <= n
    chunk = {}
    bytes = 0
    j = i
    while j <= n and (bytes == 0 or bytes + #pending_lines[j] <= PIPE_BUF_ATOMIC)
      bytes += #pending_lines[j]
      chunk[#chunk + 1] = pending_lines[j]
      j += 1
    unless write_data table.concat chunk
      ok = false
      log_warn -> { action: "nft_queue_flush_failed", dropped: n - i + 1 }
      break
    last_enqueued_seq = pending_seqs[j - 1]
    i = j
  pending_lines = {}
  pending_seqs  = {}
  pending_bytes = 0
  ok

-- Vide entièrement le tube ACK : enregistrements complets comme fragments
-- partiels éventuels (le format est de taille fixe, tout octet restant serait
-- interprété comme le début d'un ACK par wait_ack). Les enregistrements
-- complets mettent à jour last_acked_seq : un ACK purgé ici ne doit pas être
-- ré-attendu (cf. last_acked_seq / wait_ack).
drain_ack = ->
  return unless ack_rfd
  while true
    n = libc.read ack_rfd, drain_buf, 64
    break unless n and n > 0
    _record_acks drain_buf, n

--- Purge les ACK résiduels du tube et repart de zéro (démarrage du worker).
-- Un producteur redémarré repart de seq 1 : un ACK résiduel du producteur
-- précédent (seq élevé) ne doit pas pouvoir satisfaire une attente de ce
-- processus. À appeler une fois, juste après set_ack_rfd.
-- @treturn nil
reset_ack_state = ->
  drain_ack!
  last_acked_seq = 0
  nil

build_line = (kind, key, ip, rule_id, timeout, corr, item_seq, widx) ->
  -- Concaténation directe plutôt que table.concat + `.. "\n"` : la forme à
  -- table allouait un tableau de 9 champs + une string intermédiaire par
  -- ligne (cf. docs/agents/perf.md §22 ; les réponses groupées n'en émettent
  -- plus qu'une par set, cf. add_many).
  -- Le "\n" est le dernier opérande : une seule string allouée par ligne.
  LINE_VERSION .. "|" .. kind .. "|" .. key .. "|" .. ip .. "|" ..
    to_hex(rule_id or "") .. "|" .. timeout .. "|" .. tostring(item_seq) ..
    "|" .. tostring(widx or -1) .. "|" .. to_hex(corr or "") .. "\n"

--- Enfile une ligne d'insertion nft dans le tampon du lot.
-- La ligne n'est PAS écrite ici : elle rejoint le tampon, vidé en une écriture
-- (ou par tranches ≤ PIPE_BUF) par flush, appelé par get_last_seq / wait_ack /
-- send_barrier. Le retour indique donc « ligne acceptée dans le tampon », et
-- non « écrite » : un échec d'écriture est constaté au flush (log
-- `nft_queue_write_failed` / `nft_queue_flush_failed`) et le seq restera celui
-- de la dernière ligne effectivement écrite.
-- @treturn boolean false si aucun tube, tuple incomplet ou ligne trop longue
enqueue = (kind, key, ip, rule_id, timeout, corr) ->
  return false unless pipe_wfd
  return false unless kind and key and ip
  timeout = sanitize_timeout timeout
  seq += 1
  line = build_line kind, key, ip, rule_id, timeout, corr, seq, worker_idx
  return false if #line > PIPE_BUF_SAFE
  -- Tranche pleine : vider avant d'ajouter (chaque write reste ≤ PIPE_BUF).
  flush! if pending_bytes + #line > PIPE_BUF_ATOMIC
  pending_lines[#pending_lines + 1] = line
  pending_seqs[#pending_seqs + 1] = seq
  pending_bytes += #line
  true

add_ip4  = (client_ip, ip_str, rule_id, timeout, corr) -> enqueue "ip4",  client_ip, ip_str, rule_id, timeout, corr
add_ip6  = (client_ip, ip_str, rule_id, timeout, corr) -> enqueue "ip6",  client_ip, ip_str, rule_id, timeout, corr
add_mac4 = (mac, ip_str, rule_id, timeout, corr)       -> enqueue "mac4", mac,       ip_str, rule_id, timeout, corr
add_mac6 = (mac, ip_str, rule_id, timeout, corr)       -> enqueue "mac6", mac,       ip_str, rule_id, timeout, corr

-- Réserve forfaitaire (octets) de la partie non-adresses d'une ligne groupée :
-- seq et worker_idx au pire cas (20 chiffres chacun), les 9 séparateurs "|", le
-- "\n" final et le timeout le plus long accepté (16 o, cf. is_valid_timeout).
GROUP_FIXED_RESERVE = 20 + 20 + 9 + 1 + 16

--- Enfile plusieurs adresses d'un même set, en lignes IPC groupées.
-- Une réponse DNS insère N adresses dans le set de la règle (clé = IP client)
-- et N dans le set MAC : une ligne par enregistrement serait un gaspillage, le
-- contenu ne différant que par l'adresse. Cette variante porte la liste des
-- adresses dans le champ `ip` (séparateur espace, format accepté par
-- `worker_nft.parse_line`), une ligne par tranche et un `seq` par tranche
-- (l'ACK couvre tout le groupe) — cf. docs/agents/perf.md §29a.
-- Ne fait QUE découper : chaque tranche jointe par " " est confiée à `enqueue`,
-- qui construit la ligne, la valide et l'empile (une adresse ⇒ une tranche ⇒
-- ligne identique à add_ip4/add_mac4, sans cas spécial).
-- @tparam string kind    ip4|ip6|mac4|mac6
-- @tparam string key     Clé du tuple (IP client, MAC…), commune aux adresses
-- @tparam table  addrs   Adresses à insérer (liste de chaînes)
-- @tparam string rule_id Identifiant de règle (nom du set)
-- @tparam string|nil timeout Timeout nft commun aux adresses
-- @tparam string|nil corr Corrélateur (cf. build_line)
-- @treturn number Nombre d'adresses enfilées (0 si aucun tube, tuple
--   incomplet, liste vide, ou ligne trop longue pour PIPE_BUF_SAFE)
add_many = (kind, key, addrs, rule_id, timeout, corr) ->
  return 0 unless pipe_wfd
  return 0 unless kind and key and addrs
  n = #addrs
  return 0 if n == 0
  -- Budget d'octets pour les adresses d'une tranche : la ligne complète doit
  -- tenir dans PIPE_BUF_SAFE. Les champs constants sont mesurés sans les
  -- encoder (`to_hex` double exactement la longueur) ; GROUP_FIXED_RESERVE
  -- couvre seq, worker_idx, timeout et les séparateurs.
  budget = PIPE_BUF_SAFE - (#LINE_VERSION + #kind + #key +
    2 * #(rule_id or "") + 2 * #(corr or "") + GROUP_FIXED_RESERVE)
  queued = 0
  i = 1
  while i <= n
    parts = {}
    bytes = 0
    -- Au moins une adresse par tranche : une adresse plus longue que le budget
    -- part seule et enqueue rejette alors la ligne, comme une ligne unitaire.
    while i <= n and (bytes == 0 or bytes + #addrs[i] + 1 <= budget)
      parts[#parts + 1] = addrs[i]
      bytes += #addrs[i] + 1
      i += 1
    joined = parts[1]
    joined = table.concat parts, " " if #parts > 1
    break unless enqueue kind, key, joined, rule_id, timeout, corr
    queued += #parts
  queued

add_ip4_many  = (client_ip, addrs, rule_id, timeout, corr) -> add_many "ip4",  client_ip, addrs, rule_id, timeout, corr
add_ip6_many  = (client_ip, addrs, rule_id, timeout, corr) -> add_many "ip6",  client_ip, addrs, rule_id, timeout, corr
add_mac4_many = (mac, addrs, rule_id, timeout, corr)       -> add_many "mac4", mac,       addrs, rule_id, timeout, corr
add_mac6_many = (mac, addrs, rule_id, timeout, corr)       -> add_many "mac6", mac,       addrs, rule_id, timeout, corr
add_sip4 = (ip_str, rule_id, timeout, corr)            -> enqueue "sip4", ip_str,    ip_str, rule_id, timeout, corr
add_sip6 = (ip_str, rule_id, timeout, corr)            -> enqueue "sip6", ip_str,    ip_str, rule_id, timeout, corr

send_barrier = (corr) ->
  return false unless pipe_wfd
  -- Les lignes du lot doivent partir AVANT la barrière (et son ACK) : sinon
  -- worker_nft pourrait acquitter la barrière sans les avoir reçues.
  flush!
  drain_ack!
  seq += 1
  line = build_line "barrier", "_", "_", "", "0s", corr, seq, worker_idx
  ok = write_line line
  last_enqueued_seq = seq if ok
  ok

--- Vide le tampon et rend le plus grand seq effectivement écrit.
-- Le flush est ce qui rend le seq exact : si une tranche a échoué, le seq rendu
-- est celui de la dernière ligne écrite, jamais celui d'une ligne abandonnée.
-- @treturn number|nil Seq de la dernière ligne écrite depuis le dernier appel
get_last_seq = ->
  flush!
  s = last_enqueued_seq
  last_enqueued_seq = nil
  s

-- Index du worker propriétaire du tube ACK (0-based), exposé pour dériver le
-- chemin d'un verrou inter-processus propre à ce worker (cf. doh.query).
get_worker_idx = ->
  worker_idx

-- Attend l'ACK de worker_nft pour le batch courant.
-- Un ACK est un enregistrement de taille fixe (ACK_SIZE) portant le plus grand
-- `seq` appliqué par worker_nft pour ce worker. `wait_ack` ne rend la main que
-- lorsque ce seq atteint `pending_seq` : les ACK d'un batch antérieur (seq
-- strictement inférieur, p. ex. les 64 premiers éléments d'un inject coupé par
-- MAX_BATCH) sont ignorés et l'attente continue, sans dépasser le budget global
-- ACK_TIMEOUT_MS.
-- `seq` est un compteur Lua monotone par processus (jamais remis à zéro dans un
-- processus vivant) : aucun rebouclage n'est possible avant 2^53 insertions
-- (des siècles au débit réel). Un redémarrage du producteur repart de zéro ; les
-- ACK résiduels du tube sont purgés par drain_ack! avant l'injection suivante.
-- on_wait (optionnel) est appelé à chaque tour d'attente, typiquement pour
-- drainer le pipe IPC question→response pendant l'attente, sans bloquer le
-- pipe et sans toucher à l'ordre nft-avant-verdict.
wait_ack = (pending_seq, corr, on_wait) ->
  return false unless ack_rfd
  -- Toute insertion du lot doit être dans le pipe avant l'attente : un ACK ne
  -- peut pas couvrir une ligne encore tamponnée.
  flush!
  target = pending_seq or 0
  -- ACK déjà observé sur ce processus (lu par un wait_ack précédent ou purgé
  -- par drain_ack!) : ne pas re-attendre 150 ms un enregistrement qui ne sera
  -- plus réémis. L'ACK est cumulatif par worker (plus grand seq appliqué).
  return true if target > 0 and last_acked_seq >= target
  deadline = monotonic_ms! + ACK_TIMEOUT_MS
  poll_fds[0].fd     = ack_rfd
  poll_fds[0].events = POLLIN
  have = 0
  while true
    remaining = deadline - monotonic_ms!
    break if remaining <= 0
    poll_fds[0].revents = 0
    rv = libc.poll poll_fds, 1, math.min(WAIT_POLL_MS, remaining)
    if rv > 0
      n = libc.read ack_rfd, ack_rec + have, ACK_SIZE - have
      if n and n > 0
        have += n
        if have >= ACK_SIZE
          acked = ack_rec_seq!
          last_acked_seq = acked if acked > last_acked_seq
          have = 0
          return true if acked >= target
          -- ACK périmé : l'attente continue dans le MÊME budget.
      elseif n == 0
        -- Tube fermé (worker_nft absent) : rien ne viendra plus. On laisse
        -- expirer le budget au lieu de tourner à vide sur POLLHUP.
        sleep_ms WAIT_POLL_MS
    on_wait! if on_wait
  log_warn -> {
    action: "nft_ack_timeout"
    worker_idx: worker_idx
    seq: pending_seq
    corr: corr or ""
    timeout_ms: ACK_TIMEOUT_MS
  }
  false

sanitize_rule_id = (rule_id) ->
  return "" unless rule_id
  s = tostring rule_id
  return "" if #s == 0
  -- Rule IDs should be hex-decodable; limit to 63 bytes for safety
  if #s > 126
    s = s\sub 1, 126
  s

get_set_name = (kind, rule_id) ->
  rule_id = sanitize_rule_id rule_id
  if rule_id == ""
    -- No fallback to global sets: rule_id is required for per-rule sets
    if kind == "sip4"
      return "sip_peers"
    if kind == "sip6"
      return "sip_peers6"
    return nil

  if kind == "auth_mac"
    return "#{rule_id}_auth_mac"
  if kind == "auth_ip4"
    return "#{rule_id}_auth_ip4"
  if kind == "auth_ip6"
    return "#{rule_id}_auth_ip6"
  if kind == "ip4" or kind == "ip6" or kind == "mac4" or kind == "mac6"
    return "#{rule_id}_#{kind}"
  nil

--- Décrit l'insertion d'un élément : set cible + texte de l'élément.
-- Factorise `cmd_lines_for` pour que worker_nft puisse regrouper plusieurs
-- éléments d'un MÊME set en une seule instruction
-- `add element <famille> <table> <set> { e1, e2, … }` : mêmes éléments, mêmes
-- timeouts par élément, seul le nombre d'instructions nft diminue (leur coût
-- domine celui du worker nft, cf. docs/agents/perf.md §8).
-- @tparam string kind    ip4|ip6|mac4|mac6|sip4|sip6|auth_mac|auth_ip4|auth_ip6
-- @tparam string key     Clé du tuple (IP client, MAC…)
-- @tparam string ip      Valeur du tuple (IP autorisée) ; "_" pour auth_*
-- @tparam string rule_id Identifiant de règle (nom du set)
-- @tparam number|string timeout Timeout nft (assaini : valeur de repli si invalide)
-- @treturn table|nil { family, table, set_name, elem } ; nil si kind/rule_id
--                     ne permettent pas de nommer un set (comportement de
--                     get_set_name), l'appelant ignore alors l'élément comme avant.
element_spec = (kind, key, ip, rule_id, timeout) ->
  timeout = sanitize_timeout timeout
  set_name = get_set_name kind, rule_id
  return nil unless set_name

  family = nil
  simple = false
  switch kind
    when "ip4", "mac4"
      family = FAMILY
    when "ip6", "mac6"
      family = FAMILY6
    when "sip4", "auth_mac", "auth_ip4"
      family = FAMILY
      simple = true
    when "sip6", "auth_ip6"
      family = FAMILY6
      simple = true
  return nil unless family

  elem = if simple
    "#{key} timeout #{timeout}"
  else
    "#{key} . #{ip} timeout #{timeout}"
  { :family, table: TABLE, :set_name, :elem }

-- cmd_for(kind, key, ip, rule_id, timeout)
cmd_lines_for = (kind, key, ip, rule_id, timeout) ->
  spec = element_spec kind, key, ip, rule_id, timeout
  return nil unless spec
  { "add element #{spec.family} #{spec.table} #{spec.set_name} { #{spec.elem} }" }

cmd_for = (kind, key, ip, rule_id, timeout) ->
  lines = cmd_lines_for kind, key, ip, rule_id, timeout
  return nil unless lines and #lines > 0
  table.concat lines, "\n"

{ :set_wfd, :set_ack_rfd, :get_last_seq, :get_worker_idx, :wait_ack, :drain_ack, :send_barrier, :flush, :add_ip4, :add_ip6, :add_mac4, :add_mac6, :add_ip4_many, :add_ip6_many, :add_mac4_many, :add_mac6_many, :add_many, :add_sip4, :add_sip6, :cmd_for, :cmd_lines_for, :element_spec, :sanitize_timeout, :get_set_name, :sanitize_rule_id, :ACK_SIZE, :get_last_acked, :reset_ack_state, :build_line }
