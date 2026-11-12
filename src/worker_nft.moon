{ :ffi, :libc } = require "ffi_defs"
{ :run_cmd } = require "nft"
{ :cmd_for, :element_spec, :sanitize_timeout, :ACK_SIZE } = require "nft_queue"
{ :log_info, :log_warn, :log_debug, :set_action_prefix, :level_enabled } = require "log"
{ :split_fields, :from_hex, :is_ipv4_str, :is_ipv6_str, :is_valid_mac, :is_valid_timeout } = require "lib.ipc_hex"

BUF_SIZE  = 8192
MAX_BATCH = 64
EAGAIN    = 11
EWOULDBLOCK = 11
POLLIN    = 1

LINE_VERSION = "v1"

CLOCK_MONOTONIC = 1

-- Fenêtre de saut du cache d'upsert : min(timeout/10, SKIP_WINDOW_MAX_S).
-- Une entrée du cache plus vieille que cette fenêtre ne peut plus rien faire
-- sauter : elle sert aussi de horizon de purge (CACHE_STALE_S).
SKIP_WINDOW_MAX_S = 5
CACHE_STALE_S     = SKIP_WINDOW_MAX_S
-- Borne du cache d'upsert (clé famille/table/set/élément) : au-delà, purge des
-- entrées périmées puis éviction des plus anciennes jusqu'à 3/4 de la borne.
-- 4096 entrées pleines mesurées à 932 Kio (233 o/entrée, clés réalistes) :
-- `nix develop --command bash -c "luajit tmp/measure_cache.lua"` →
-- `tmp/cache_mem.txt` (chiffré dans tmp/nftcache_report.md).
CACHE_MAX_ENTRIES = 4096

-- Secondes par unité de timeout nft (forme "30s", "2m", "1h", "5d", "1w", "60").
TIMEOUT_UNIT_S = { s: 1, m: 60, h: 3600, d: 86400, w: 604800 }

read_buf  = ffi.new "char[?]", BUF_SIZE
-- Enregistrement d'ACK : uint64 natif portant le plus grand `seq` appliqué
-- pour le worker destinataire (voir nft_queue.wait_ack).
ack_val   = ffi.new "uint64_t[1]"
poll_fd   = ffi.new "struct pollfd[1]"
ts_req    = ffi.new "timespec_t[1]"

validate_item = (kind, key, ip) ->
  if kind == "ip4"
    return false unless is_ipv4_str(key) and is_ipv4_str(ip)
  elseif kind == "ip6"
    return false unless is_ipv6_str(key) and is_ipv6_str(ip)
  elseif kind == "mac4"
    return false unless is_valid_mac(key) and is_ipv4_str(ip)
  elseif kind == "mac6"
    return false unless is_valid_mac(key) and is_ipv6_str(ip)
  elseif kind == "sip4"
    return false unless is_ipv4_str(key)
  elseif kind == "sip6"
    return false unless is_ipv6_str(key)
  else
    return false
  true

parse_line = (line) ->
  parts = split_fields line
  return nil, "field_count" unless #parts == 9
  return nil, "version" unless parts[1] == LINE_VERSION
  kind, key, ip = parts[2], parts[3], parts[4]
  return nil, "tuple" unless validate_item kind, key, ip
  rule_id, err_rule = from_hex parts[5]
  return nil, "rule_id_#{err_rule}" if err_rule
  timeout = sanitize_timeout parts[6]
  seq = tonumber parts[7]
  return nil, "seq" unless seq and seq >= 0
  widx = tonumber parts[8]
  return nil, "worker_idx" unless widx
  corr, err_corr = from_hex parts[9]
  return nil, "corr_#{err_corr}" if err_corr
  {
    :kind
    :key
    :ip
    :rule_id
    :timeout
    -- La ligne porte-t-elle elle-même un timeout valide ? Sans lui, le saut du
    -- cache d'upsert est désactivé (le repli de sanitize_timeout s'applique).
    has_timeout: is_valid_timeout parts[6]
    :seq
    :widx
    :corr
  }, nil

-- Acquitte le traitement du batch pour un worker : enregistrement de taille
-- fixe (ACK_SIZE octets) portant le plus grand `seq` que ce flush a appliqué
-- pour ce worker. Une écriture ≤ PIPE_BUF est atomique : le lecteur ne voit
-- jamais un ACK entrelacé avec un autre. Échec d'écriture (tube plein) =
-- ACK perdu → le producteur ira au timeout, comme avant.
send_ack = (ack_wfds, widx, seq) ->
  return unless widx and widx >= 0
  wfd = ack_wfds[widx + 1]
  return unless wfd
  ack_val[0] = seq or 0
  libc.write wfd, ack_val, ACK_SIZE

-- ── Cache d'upsert ────────────────────────────────────────────────────────────
-- Les producteurs réinsèrent les mêmes éléments à chaque réponse DNS pour
-- rafraîchir leur timeout : les sets ne grandissent pas (delta mesuré nul,
-- docs/agents/perf.md §16.3) mais chaque réinsertion coûte une transaction
-- nft (worker nft à 50-65 % d'un vCPU). Le cache retient, par clé
-- (famille/table, set, élément), l'instant ET le timeout de la dernière
-- insertion **appliquée avec succès** ; une ligne récente est alors sautée.
-- Le cache ne s'applique qu'aux sets alimentés EXCLUSIVEMENT par worker_nft :
-- kinds auth_* et sets vidés/supprimés par un autre processus en sont exclus
-- (cf. UNCACHEABLE_KINDS / UNCACHEABLE_SETS avant `cache_key_of`).

--- Secondes monotones (horloge du cache d'upsert).
-- @treturn number
monotonic_s = ->
  libc.clock_gettime CLOCK_MONOTONIC, ts_req
  tonumber(ts_req[0].tv_sec) + tonumber(ts_req[0].tv_nsec) / 1000000000

--- Convertit un timeout nft ("30s", "2m", "1h", "5d", "1w", "60") en secondes.
-- @tparam string|nil t Timeout textuel (cf. nft_queue.build_line)
-- @treturn number|nil Secondes, ou nil si la forme est inconnue
timeout_to_seconds = (t) ->
  return nil unless type(t) == "string"
  digits, unit = t\match "^(%d+)([smhdw]?)$"
  return nil unless digits
  mult = 1
  if unit and unit != ""
    mult = TIMEOUT_UNIT_S[unit]
    return nil unless mult
  tonumber(digits) * mult

--- Crée un cache d'upsert borné.
-- @tparam table|nil opts { max: nombre maximal d'entrées, now: horloge () }
-- @treturn table Cache { entries, size, max, skipped, evicted, now }
new_cache = (opts) ->
  opts = opts or {}
  {
    entries: {}
    size: 0
    max: opts.max or CACHE_MAX_ENTRIES
    skipped: 0
    evicted: 0
    now: opts.now or monotonic_s
  }

-- Éviction : purge des entrées périmées (âge ≥ CACHE_STALE_S — inutiles au
-- saut, la fenêtre ne dépasse jamais cette valeur), puis, si la borne est
-- toujours atteinte, suppression des plus anciennes jusqu'à 3/4 de `max`.
-- O(max) mais seulement sur débordement.
cache_evict = (cache) ->
  now = cache.now!
  for k, e in pairs cache.entries
    if now - e.t >= CACHE_STALE_S
      cache.entries[k] = nil
      cache.size -= 1
  return if cache.size < cache.max
  target = math.floor(cache.max * 3 / 4)
  while cache.size > target
    oldest_k, oldest_t = nil, nil
    for k, e in pairs cache.entries
      if oldest_t == nil or e.t < oldest_t
        oldest_k, oldest_t = k, e.t
    break unless oldest_k
    cache.entries[oldest_k] = nil
    cache.size -= 1
    cache.evicted += 1
  nil

--- Insère (ou rafraîchit) l'entrée d'une insertion réussie.
-- @tparam table cache Cache créé par new_cache
-- @tparam string key Clé famille|table|set|élément
-- @tparam number|nil timeout_s Timeout demandé, en secondes
-- @treturn nil
cache_put = (cache, key, timeout_s) ->
  return unless cache and key
  now = cache.now!
  entry = cache.entries[key]
  if entry
    entry.t = now
    entry.timeout_s = timeout_s
    return
  cache_evict cache if cache.size >= cache.max
  cache.entries[key] = { t: now, timeout_s: timeout_s }
  cache.size += 1
  nil

--- Supprime l'entrée d'une clé (invalidation ciblée après un échec nft).
-- @treturn nil
cache_drop = (cache, key) ->
  return unless cache and key and cache.entries[key]
  cache.entries[key] = nil
  cache.size -= 1
  nil

--- Vide le cache entier (invalidation globale : flush/reload des sets).
-- @treturn nil
cache_clear = (cache) ->
  return unless cache
  cache.entries = {}
  cache.size = 0
  nil

-- ── Exclusions du cache ────────────────────────────────────────────────────────
-- Le cache ne s'applique (ni saut ni enregistrement) qu'aux sets alimentés
-- EXCLUSIVEMENT par worker_nft. Deux familles d'exclusion :
-- 1. kinds auth_* (`auth_mac`/`auth_ip4`/`auth_ip6`, cf.
--    `nft_queue.add_auth_mac/add_auth_ip4/add_auth_ip6`) : leurs sets
--    `{rule_id}_auth_*` sont supprimés par le processus AUTH avec son propre
--    contexte nft (`delete_rule_auth_sets`, `src/auth/nft_auth_sets.moon:29,31`,
--    appelé par `src/auth/handlers.moon:248` au logout) : une insertion
--    récente ne dit rien de l'état actuel du set.
-- 2. sets vidés/supprimés hors de worker_nft (greps `delete element` /
--    `flush set` dans `src/`) : `authenticated_*`
--    (`src/auth/nft_sessions.moon:40,53,85` : logout/bye/expiration) et
--    `ip*_dest_whitelist` (`src/ip_whitelist.moon:31-32` : chaque SIGHUP).
-- Aucun kind actuel n'atteint ces sets globaux (`get_set_name`,
-- `src/nft_queue.moon:259-277`) : la liste les protège si un chemin
-- d'écriture venait à être ajouté.
UNCACHEABLE_KINDS = {
  auth_mac: true
  auth_ip4: true
  auth_ip6: true
}

UNCACHEABLE_SETS = {
  authenticated_ips: true
  authenticated_ips6: true
  authenticated_macs: true
  ip4_dest_whitelist: true
  ip6_dest_whitelist: true
}

--- Ce set est-il exclu du cache d'upsert (vidé ou supprimé hors de worker_nft) ?
-- @tparam string|nil set_name Nom du set nft
-- @treturn boolean true si le cache s'y applique
cacheable_set = (set_name) ->
  not (set_name and UNCACHEABLE_SETS[set_name])

--- Clé de cache (famille|table|set|élément) de l'item, calculée une fois puis
-- réutilisée par build_batch (via `item.spec`).
-- @tparam table item Item parsé par parse_line
-- @treturn string|nil nil si kind/rule_id ne permettent pas de nommer un set,
--   ou si l'item est exclu du cache (kind auth_*, set manipulé hors
--   worker_nft) : sans clé, ni saut ni enregistrement ne peuvent avoir lieu.
cache_key_of = (item) ->
  return item.cache_key if item.cache_key
  spec = element_spec item.kind, item.key, item.ip, item.rule_id, item.timeout
  if spec
    item.spec = spec
    cacheable = not UNCACHEABLE_KINDS[item.kind] and cacheable_set spec.set_name
    if cacheable
      item.cache_key = "#{spec.family}|#{spec.table}|#{spec.set_name}|#{item.key}|#{item.ip}"
      item.timeout_s = timeout_to_seconds item.timeout
  item.cache_key

-- Ajoute un item à `pending` avec déduplication par
-- (kind,key,ip,timeout,rule_id). Le nom du set nft dépend de rule_id
-- (`#{rule_id}_#{kind}`) : deux règles distinctes autorisant le même couple
-- (client, IP) doivent produire deux insertions.
-- Retourne true si l'item a été ajouté (nouvelle clé), false si c'est un doublon.
-- Permet à l'appelant de tenir un compteur incrémental sans re-parcourir
-- `pending` (pairs) à chaque tour de boucle.
--
-- Cache d'upsert (`cache` fourni) : l'ajout est **sauté** quand la même clé a
-- été insérée avec succès il y a moins de `min(timeout/10, SKIP_WINDOW_MAX_S)`
-- ET que le nouveau timeout n'est pas plus long que le précédent de plus que
-- cette même fenêtre (sinon on raccourcirait la durée de vie résiduelle).
-- Sans timeout valide dans la ligne (`has_timeout` faux) : aucun saut. L'item
-- sauté n'entre pas dans `pending` mais son seq reste acquitté par l'appelant
-- (l'élément existe déjà dans nft).
-- Items exclus du cache (kinds auth_*, sets vidés/supprimés hors worker_nft) :
-- `cache_key_of` ne leur attribue aucune clé → ni saut ni enregistrement.
-- @tparam table pending Items en attente du prochain lot
-- @tparam table item   Item parsé par parse_line
-- @tparam table|nil cache Cache d'upsert (nil = aucun saut)
-- @treturn boolean true si l'item a été ajouté, false si doublon ou sauté
try_add_pending = (pending, item, cache) ->
  entry_key = "#{item.kind}|#{item.key}|#{item.ip}|#{item.timeout}|#{tostring item.rule_id}"
  return false if pending[entry_key]
  cache_key_of item
  if cache and item.has_timeout and item.cache_key and item.timeout_s
    entry = cache.entries[item.cache_key]
    if entry and entry.timeout_s
      window = math.min(item.timeout_s / 10, SKIP_WINDOW_MAX_S)
      if window > 0 and (cache.now! - entry.t) < window and item.timeout_s <= entry.timeout_s + window
        cache.skipped += 1
        return false
  pending[entry_key] = item
  true

--- Prépare les commandes nft d'un lot : une instruction par set (regroupement)
-- plus la liste des instructions élément par élément (repli).
-- Le regroupement conserve exactement les mêmes éléments et les mêmes timeouts
-- par élément (`ip timeout Ns` dans la liste) ; il ne change que le nombre
-- d'instructions soumises à libnftables, dont le coût domine celui du worker
-- (0,22-0,27 ms par instruction mesuré, docs/agents/perf.md §8).
-- @tparam table pending Items { kind, key, ip, rule_id, timeout }
-- @treturn table { cmds = { instructions groupées }, singles = { élément par
--   élément }, items = items alignés sur singles, count = nombre d'éléments
--   retenus }
build_batch = (pending) ->
  groups = {}
  order = {}
  singles = {}
  items = {}
  count = 0
  for _, item in pairs pending
    -- `item.spec` est déjà calculé par cache_key_of (try_add_pending) : le
    -- recalcul n'a lieu que pour un item inséré hors du chemin usuel.
    spec = item.spec or element_spec item.kind, item.key, item.ip, item.rule_id, item.timeout
    continue unless spec
    count += 1
    gkey = "#{spec.family}|#{spec.table}|#{spec.set_name}"
    group = groups[gkey]
    unless group
      group = { family: spec.family, table: spec.table, set_name: spec.set_name, elems: {} }
      groups[gkey] = group
      order[#order + 1] = gkey
    group.elems[#group.elems + 1] = spec.elem
    singles[#singles + 1] = "add element #{spec.family} #{spec.table} #{spec.set_name} { #{spec.elem} }"
    items[#items + 1] = item

  cmds = {}
  for gkey in *order
    g = groups[gkey]
    cmds[#cmds + 1] = "add element #{g.family} #{g.table} #{g.set_name} { #{table.concat g.elems, ", "} }"
  { :cmds, :singles, :items, :count }

--- Vide `pending` en l'appliquant, acquitte les workers, puis met à jour le
-- cache d'upsert.
-- @tparam table pending    Items en attente (vidé ici)
-- @tparam table ack_queue  ACK à émettre { widx, seq, … }
-- @tparam table ack_wfds   FD d'ACK indexés par worker
-- @tparam table|nil cache  Cache d'upsert (nil = pas de saut ni d'enregistrement)
flush_batch = (pending, ack_queue, ack_wfds, cache) ->
  rule11_count = 0
  rule11_items = {}
  for _, item in pairs pending
    if item.rule_id == "rule_11"
      rule11_count += 1
      rule11_items[#rule11_items + 1] = "#{item.kind}:#{item.key}>#{item.ip}"
  batch = build_batch pending
  for k in pairs pending
    pending[k] = nil

  -- Compteur cumulé de lignes sautées par le cache depuis le démarrage du
  -- worker (pas de log de stats périodique dans worker_nft : reporté sur les
  -- logs de lot DEBUG existants).
  skipped = cache and cache.skipped or 0

  if batch.count > 0
    cmd = table.concat batch.cmds, "\n"
    ok, err = run_cmd cmd, { quiet: true }
    if rule11_count > 0 and level_enabled "DEBUG"
      -- Une ligne par lot nft (donc potentiellement par requête) : DEBUG.
      log_debug -> { action: "nft_batch_rule", rule_id: "rule_11", count: rule11_count, ok: ok, items: table.concat(rule11_items, " ") }
    if ok
      -- Transaction groupée appliquée : chaque élément du lot est désormais
      -- présent dans nft → instant + timeout enregistrés pour le saut.
      if cache
        for item in *batch.items
          key = cache_key_of item
          cache_put cache, key, item.timeout_s if key and item.timeout_s
      log_debug -> { action: "batch_ok", count: batch.count, groups: #batch.cmds, acks: #ack_queue, skipped: skipped }
    else
      log_warn -> { action: "batch_failed", count: batch.count, groups: #batch.cmds, acks: #ack_queue, err: err or "", skipped: skipped }
      -- Transaction atomique rejetée : rien du lot n'a été appliqué → les
      -- entrées de cache concernées sont invalidées (elles ne peuvent plus
      -- servir à sauter une future réinsertion).
      if cache
        for item in *batch.items
          key = cache_key_of item
          cache_drop cache, key if key
      -- Repli élément par élément : un élément invalide ne doit pas emporter
      -- les autres (comportement historique, préservé).
      for i, line in ipairs batch.singles
        ok_one, err_one = run_cmd line, { quiet: true }
        if ok_one and cache
          item = batch.items[i]
          key = cache_key_of item
          cache_put cache, key, item.timeout_s if key and item.timeout_s
        log_warn -> { action: "single_failed", err: err_one or "", cmd: line } unless ok_one
  else
    log_debug -> { action: "batch_ack_only", acks: #ack_queue, skipped: skipped }

  -- Un ACK par worker (widx) présent dans le batch, portant le PLUS GRAND seq
  -- appliqué pour ce worker. Le producteur attend le seq de sa dernière ligne :
  -- un inject coupé par MAX_BATCH sur plusieurs flushes n'est donc acquitté
  -- qu'une fois toutes ses lignes traitées (l'ACK du premier flush a un seq
  -- antérieur et est ignoré par wait_ack).
  -- L'ACK est émis même si la transaction nft a échoué (après les reprises
  -- ligne à ligne) : il acquitte le *traitement* du batch, pas son succès —
  -- sémantique inchangée ; le producteur applique ensuite add_failure_policy.
  workers_to_ack = {}
  for ack in *ack_queue
    prev = workers_to_ack[ack.widx]
    seq = ack.seq or 0
    workers_to_ack[ack.widx] = seq if prev == nil or seq > prev
  for widx, seq in pairs workers_to_ack
    send_ack ack_wfds, widx, seq
  for i = #ack_queue, 1, -1
    ack_queue[i] = nil

--- Boucle principale du worker.
-- @tparam number rfd        Pipe `nft` en lecture
-- @tparam table|nil ack_wfds FD d'ACK indexés par worker
-- @tparam table|nil cache   Cache d'upsert (injectable pour les tests ;
--   défaut : nouveau cache borné propre au processus)
run = (rfd, ack_wfds, cache) ->
  set_action_prefix "nft_"
  ack_wfds = ack_wfds or {}
  cache = cache or new_cache!
  log_info -> { action: "worker_start", rfd: rfd, ack_workers: #ack_wfds }
  pending       = {}
  pending_count = 0
  ack_queue     = {}
  partial       = ""

  poll_fd[0].fd     = rfd
  poll_fd[0].events = POLLIN

  while true
    -- Bloque jusqu'à l'arrivée de données, SAUF s'il reste déjà une ligne
    -- complète bufferisée dans `partial` (cas d'un batch tronqué à MAX_BATCH au
    -- tour précédent) : on la traite immédiatement sans attendre le pipe. Un
    -- `partial` ne contenant qu'un fragment incomplet (sans `\n`) ne suffit pas :
    -- on bloque alors sur poll en attendant la fin de la ligne.
    unless partial\find "\n", 1, true
      poll_fd[0].revents = 0
      libc.poll poll_fd, 1, -1

    -- Draine : on consomme d'abord les lignes complètes déjà bufferisées, puis on
    -- lit le pipe (non bloquant) jusqu'à EAGAIN ou MAX_BATCH (borne la taille de
    -- la transaction nft).
    batch_full = false
    while not batch_full
      -- 1. Consommer les lignes complètes présentes dans `partial`.
      while true
        nl = partial\find "\n", 1, true
        break unless nl
        line = partial\sub 1, nl - 1
        partial = partial\sub nl + 1
        continue if #line == 0
        item, parse_err = parse_line line
        if item
          ack_queue[#ack_queue + 1] = { widx: item.widx, seq: item.seq, corr: item.corr, rule_id: item.rule_id }
          -- Le seq est acquitté même si l'ajout est sauté ou est un doublon :
          -- l'ACK porte le traitement de la ligne, pas son insertion.
          pending_count += 1 if try_add_pending pending, item, cache
        else
          log_warn -> { action: "nft_invalid_message", reason: parse_err or "parse_failed", raw: line\sub(1, 220) }
        if pending_count >= MAX_BATCH
          batch_full = true
          break
      break if batch_full

      -- 2. Plus de ligne complète bufferisée : lire davantage (non bloquant).
      n = libc.read rfd, read_buf, BUF_SIZE
      if n and n > 0
        partial = partial .. ffi.string read_buf, n
        -- Garde-fou : un fragment géant sans `\n` ne doit pas croître sans fin.
        if #partial > 4096 and not partial\find "\n", 1, true
          log_warn -> { action: "nft_partial_oversize", size: #partial }
          partial = ""
      elseif n == 0
        -- EOF (tous les producteurs ont fermé) : on flush ce qui reste avant
        -- de sortir, pour un arrêt propre (best-effort).
        flush_batch pending, ack_queue, ack_wfds, cache if pending_count > 0 or #ack_queue > 0
        log_warn -> { action: "pipe_closed", rfd: rfd }
        return
      else
        errno_p = libc.__errno_location!
        errno = if errno_p then errno_p[0] else 0
        break if errno == EAGAIN or errno == EWOULDBLOCK   -- pipe drainé → flush
        log_warn -> { action: "read_failed", rfd: rfd, errno: errno }
        break

    -- Flush dès que le pipe est drainé (ou le batch plein) : la latence est
    -- minimale (plus d'attente FLUSH_MS), et la coalescence reste naturelle
    -- sous charge — pendant la durée d'un flush, le pipe accumule les insertions
    -- suivantes, formant le batch d'après.
    if pending_count > 0 or #ack_queue > 0
      flush_batch pending, ack_queue, ack_wfds, cache
      pending_count = 0

{ :run, :parse_line, :flush_batch, :build_batch, :try_add_pending, :split_fields, :from_hex, :new_cache, :cache_put, :cache_drop, :cache_clear, :cache_key_of, :cacheable_set, :timeout_to_seconds }
