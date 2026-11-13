--
-- SPDX-FileCopyrightText: (c) 2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Banc CPU du worker `nft` réel : boucle `worker_nft.run`, tube réel,
-- `nft` (libnftables) remplacé par un stub inerte.
--
-- Objectif : chiffrer le CPU **du worker nft seul**, par ligne et par tour de
-- boucle, et comparer deux versions du code (ou deux réglages GC) sans cible
-- distante ni NFQUEUE. Le banc :
--   * fabrique des lignes avec le VRAI `nft_queue.build_line` (mêmes champs
--     qu'en production : ip4+mac4 par enregistrement A, rule_id, timeout
--     `rr_timeout`, corrélateur de 16 octets propre à chaque réponse) ;
--   * charge `worker_nft` réel après avoir remplacé `nft.run_cmd` par un stub
--     qui rend `true` (aucune transaction libnftables : on mesure le coût du
--     worker, pas celui de nft — identique dans les deux versions comparées) ;
--   * `fork` un enfant qui exécute `worker_nft.run` sur l'extrémité lecture
--     d'un tube non bloquant, et alimente l'extrémité écriture à un débit
--     contrôlé (réponses/s × lignes/réponse) ;
--   * lit le CPU de l'enfant dans `/proc/<pid>/stat` (utime+stime, même métrique
--     que les campagnes de charge) sur trois fenêtres : charge, temps mort
--     (`poll` bloqué, aucun tour), et total jusqu'à EOF.
--
-- Le nombre de **tours de boucle** est piloté par `--turns` (réponses par
-- écriture) : à débit de lignes constant, `turns=1` fait un tour par réponse,
-- `turns=8` un tour pour huit. La différence de CPU/s entre les deux donne le
-- coût d'un tour à vide (réveil `poll` + `read` + `gc.guard!` + `gc.idle!`),
-- sans toucher au code mesuré.
--
-- Mesure d'allocation (`--alloc`) : même charge rejouée en processus, GC
-- arrêté, `collectgarbage "count"` avant/après → octets par ligne.
--
-- Usage (cf. src/bench/README.md) :
--   make bench-nftcpu
--   make bench-nftcpu NP_EXTRA="--turns 1 --duration 10 --repeat 3"
--   make bench-nftcpu NP_EXTRA="--gc-idle-step 0"      # A/B d'un réglage GC
--
-- Sorties : `tmp/bench/nftcpu/` uniquement.

config = require "config"
{ :to_hex } = require "lib.ipc_hex"

--- Applique la configuration du banc (famille/table nft absente, journal).
-- Appelé par `main` AVANT le require de nft_queue/worker_nft : le module reste
-- sans effet de bord à son chargement (les specs peuvent le require).
-- @treturn table config
setup_config = ->
  config.runtime = config.runtime or {}
  config.runtime.log_level = "INFO"
  config.nft = config.nft or {}
  config.nft.family = "bridge"
  config.nft.family6 = "bridge"
  -- Table volontairement absente : aucun set n'est créé, et un éventuel
  -- `nft_run_cmd` résiduel échouerait sans effet sur un ruleset vivant.
  config.nft.table = "nftcpu_bench_no_table"
  config.nft.ip_timeout = "2m"
  config

{ :ffi, :libc } = require "ffi_defs"

-- `open`/`dup2` ne sont pas dans ffi_defs (jamais nécessaires aux workers) :
-- déclarations locales au banc, dans un pcall (redéfinition inoffensive).
for decl in *{
  "int dup2(int oldfd, int newfd);"
  "int open(const char *pathname, int flags);"
}
  pcall ffi.cdef, decl

OUT_DIR = "tmp/bench/nftcpu"

CLOCK_MONOTONIC = 1
O_WRONLY        = 1
O_NONBLOCK      = 2048
F_SETPIPE_SZ    = 1031
PIPE_BYTES      = 1048576   -- 64 réponses × ~1,3 Ko de lignes nft
EAGAIN          = 11
WNOHANG         = 1

-- Profil identique à §21 de docs/agents/perf.md : client authentifié unique,
-- 8 enregistrements A par réponse → add_ip4 + add_mac4 par enregistrement
-- (response_inject.inject), soit 16 lignes nft par réponse.
CLIENT     = "10.35.1.2"
MAC        = "d8:d3:85:63:6b:27"
RULE_ID    = "r_utilisateurs"
TIMEOUT    = "660s"   -- rr_timeout(60) avec la grâce par défaut (600 s)
ADDRS = {
  "100.64.0.11", "100.64.0.12", "100.64.0.13", "100.64.0.14"
  "100.64.0.15", "100.64.0.16", "100.64.0.17", "100.64.0.18"
}

ts_req   = ffi.new "timespec_t[1]"
sleep_req = ffi.new "timespec_t[1]"
corr_buf = ffi.new "uint8_t[16]"

--- Secondes monotones.
-- @treturn number
monotonic_s = ->
  libc.clock_gettime CLOCK_MONOTONIC, ts_req
  tonumber(ts_req[0].tv_sec) + tonumber(ts_req[0].tv_nsec) / 1000000000

--- Dort `ms` millisecondes.
-- @tparam number ms Durée
-- @treturn nil
sleep_ms = (ms) ->
  sleep_req[0].tv_sec  = math.floor ms / 1000
  sleep_req[0].tv_nsec = (ms % 1000) * 1000000
  libc.nanosleep sleep_req, nil

--- Corrélateur de 16 octets distinct à chaque réponse (comme un jeton aléatoire).
-- @tparam number i Numéro de réponse
-- @treturn string 16 octets
corr_of = (i) ->
  corr_buf[0] = i % 256
  corr_buf[1] = math.floor(i / 256) % 256
  corr_buf[2] = math.floor(i / 65536) % 256
  corr_buf[3] = math.floor(i / 16777216) % 256
  ffi.string corr_buf, 16

--- Ligne IPC de repli, format `v1|kind|key|ip|hex(rule)|timeout|seq|widx|hex(corr)`.
-- `nft_queue.build_line` n'est exporté que depuis d-alloc ; pour mesurer une
-- version antérieure (comparaison avant/après), le banc reproduit ici le même
-- format, à l'octet près (vérifié par `tests/unit/bench/nft_cpu_spec.moon`).
-- @tparam string kind    Famille d'élément
-- @tparam string key     Clé
-- @tparam string ip      Valeur
-- @tparam string rule_id Identifiant de règle
-- @tparam string timeout Timeout nft
-- @tparam string corr    Corrélateur brut
-- @tparam number seq     Seq
-- @tparam number widx    Index worker
-- @treturn string Ligne terminée par "\n"
build_line_fallback = (kind, key, ip, rule_id, timeout, corr, item_seq, widx) ->
  "v1|" .. kind .. "|" .. key .. "|" .. ip .. "|" ..
    to_hex(rule_id or "") .. "|" .. timeout .. "|" .. tostring(item_seq) ..
    "|" .. tostring(widx or -1) .. "|" .. to_hex(corr or "") .. "\n"

--- Lignes IPC d'une réponse (16 par défaut), encodées par `nft_queue.build_line`.
-- @tparam table  nq                Module nft_queue mesuré
-- @tparam number first_response    Numéro de la première réponse du tour
-- @tparam number turns             Nombre de réponses dans le tour
-- @tparam number lines_per_response Lignes par réponse
-- @tparam number seq0              Premier seq (monotone sur tout le passage)
-- @treturn string Lignes concaténées (prêtes à écrire)
-- @treturn number Dernier seq utilisé
build_turn = (nq, first_response, turns, lines_per_response, seq0) ->
  line_of = nq.build_line or build_line_fallback
  out = {}
  seq = seq0
  for r = first_response, first_response + turns - 1
    corr = corr_of r
    widx = r % 2
    for k = 1, lines_per_response
      addr = ADDRS[(k - 1) % #ADDRS + 1]
      kind = (k % 2 == 1) and "ip4" or "mac4"
      key  = (kind == "ip4") and CLIENT or MAC
      seq += 1
      out[#out + 1] = line_of kind, key, addr, RULE_ID, TIMEOUT, corr, seq, widx
  table.concat(out), seq

--- Écrit tout `data` sur un fd non bloquant, en réessayant sur EAGAIN.
-- @tparam number fd   Descripteur
-- @tparam string data Données
-- @treturn boolean true si tout a été écrit
write_all = (fd, data) ->
  n = #data
  off = 0
  ptr = ffi.cast "const char*", data
  while off < n
    w = libc.write fd, ptr + off, n - off
    if w and w > 0
      off += w
    else
      errno_p = libc.__errno_location!
      errno = if errno_p then errno_p[0] else 0
      return false if errno != EAGAIN
      sleep_ms 1
  true

--- CPU consommé par un processus (utime + stime, jiffies).
-- @tparam number pid PID
-- @treturn number|nil Jiffies cumulées
stat_cpu_ticks = (pid) ->
  fh = io.open "/proc/" .. pid .. "/stat"
  return nil unless fh
  s = fh\read "*l"
  fh\close!
  return nil unless s
  tail = s\match "%)%s+(.*)$"
  return nil unless tail
  f = {}
  for tok in tail\gmatch "%S+"
    f[#f + 1] = tok
  -- `tail` commence au champ 3 (state) : utime = champ 14 → f[12].
  u  = tonumber f[12]
  st = tonumber f[13]
  return nil unless u and st
  u + st

--- HZ du noyau (jiffies par seconde).
-- @treturn number
clock_ticks = ->
  fh = io.popen "getconf CLK_TCK 2>/dev/null"
  v = fh and fh\read "*l"
  fh\close! if fh
  tonumber(v) or 100

--- Nombre de cœurs logiques (info de rapport).
-- @treturn number
cpu_count = ->
  fh = io.open "/proc/cpuinfo"
  return 0 unless fh
  n = 0
  for line in fh\lines!
    n += 1 if line\match "^processor%s*:"
  fh\close!
  n

-- ── Stub nft et chargement des modules mesurés ───────────────────────

--- Remplace `nft` par un stub inerte AVANT le require du worker.
-- @treturn table Stub installé
install_nft_stub = ->
  stub = {
    run_cmd: (cmd, opts) -> true, nil
    cleanup: -> nil
  }
  package.loaded["nft"] = stub
  stub

--- Applique le réglage GC comme le fait la production AVANT les forks.
-- Avec `lib.gc_tune` (dev ≥ d-gctune) : `normalize` + `apply!` du module réel.
-- Sans lui (≤ ecdf4ab) : `setpause`/`setstepmul` depuis `runtime.gc_pause` /
-- `runtime.gc_stepmul`, comme `src/main.moon` à l'époque.
-- @tparam table o Options CLI (surcharges gc_*)
-- @treturn table Valeurs effectives { pause, stepmul, idle_step, max_heap_mb }
apply_gc = (o) ->
  gc_tune = nil
  unless o.legacy_gc
    ok, mod = pcall require, "lib.gc_tune"
    gc_tune = mod if ok
  if gc_tune
    config.gc = config.gc or {}
    for key in *{"pause", "stepmul", "idle_step", "max_heap_mb"}
      v = o["gc_" .. key]
      config.gc[key] = v if v != nil
    state = gc_tune.new config.gc
    state.apply!
    return state.values
  pause   = o.gc_pause or config.runtime.gc_pause
  stepmul = o.gc_stepmul or config.runtime.gc_stepmul
  collectgarbage "setpause", pause if pause
  collectgarbage "setstepmul", stepmul if stepmul
  {
    pause: pause or 200
    stepmul: stepmul or 200
    idle_step: 0
    max_heap_mb: 0
  }

-- ── Mesure CPU ───────────────────────────────────────────────────────

--- Alimente le tube au débit demandé pendant `duration` secondes.
-- @tparam table  nq    Module nft_queue
-- @tparam number wfd   extrémité écriture
-- @tparam table  o     Options
-- @tparam number turns Réponses par écriture
-- @tparam number seq0  Premier seq
-- @treturn number Nombre de réponses écrites
-- @treturn number Durée réelle (s)
-- @treturn number Dernier seq utilisé
feed = (nq, wfd, o, turns, seq0) ->
  t0 = monotonic_s!
  deadline = t0 + o.duration
  period = turns / o.qps
  sent = 0
  seq = seq0
  while true
    now = monotonic_s!
    break if now >= deadline
    data, seq = build_turn nq, sent + 1, turns, o.lines, seq
    write_all wfd, data
    sent += turns
    -- Rattrapage : on ne dort que si l'on est en avance sur la consigne.
    target = t0 + (sent / o.qps)
    dt = target - monotonic_s!
    sleep_ms dt * 1000 if dt > 0
  sent, monotonic_s! - t0, seq

--- Exécute un passage : fork du worker réel, alimentation, mesures /proc.
-- @tparam table  wnft   Module worker_nft
-- @tparam table  nq     Module nft_queue
-- @tparam table  o      Options
-- @tparam number turns  Réponses par écriture
-- @tparam number hz     Jiffies/seconde
-- @treturn table Résultat { feed_cpu_s, feed_wall_s, idle_cpu_s, total_cpu_s,
--   responses, lines, turns_executed }
measure_once = (wnft, nq, o, turns, hz) ->
  fds = ffi.new "int[2]"
  rc = libc.pipe2 fds, O_NONBLOCK
  error "pipe2() échoué" if rc != 0
  rfd = tonumber fds[0]
  wfd = tonumber fds[1]
  libc.fcntl wfd, F_SETPIPE_SZ, PIPE_BYTES

  pid = libc.fork!
  error "fork() échoué" if pid < 0
  if pid == 0
    -- Enfant : worker nft réel ; sorties neutralisées (aucun log dans tmp/).
    libc.close wfd
    devnull = libc.open "/dev/null", O_WRONLY
    if devnull >= 0
      libc.dup2 devnull, 1
      libc.dup2 devnull, 2
      libc.close devnull if devnull > 2
    wnft.run rfd
    libc._exit 0

  libc.close rfd
  sleep_ms 250   -- démarrage du worker (log worker_start, application GC)
  base = stat_cpu_ticks pid
  error "CPU enfant illisible" unless base

  sent, feed_wall, seq = feed nq, wfd, o, turns, 0
  after_feed = stat_cpu_ticks(pid) or base

  sleep_ms o.idle * 1000
  after_idle = stat_cpu_ticks(pid) or after_feed

  libc.close wfd
  final = after_idle
  status = ffi.new "int[1]"
  while true
    last = stat_cpu_ticks pid
    final = last if last
    break if libc.waitpid(pid, status, WNOHANG) == pid
    sleep_ms 5

  {
    :sent, :feed_wall, :seq
    feed_cpu_s: (after_feed - base) / hz
    idle_cpu_s: (after_idle - after_feed) / hz
    total_cpu_s: (final - base) / hz
    turns_executed: math.ceil sent / turns
  }

-- ── Mesure d'allocation ──────────────────────────────────────────────

--- Alloue par ligne du chemin worker nft (parse + pending + flush), GC arrêté.
-- Le tube, le poll et l'ACK ne sont pas mesurés ici : seul le travail Lua
-- (parse_line, try_add_pending, build_batch, flush_batch) compte.
-- @tparam table  wnft Module worker_nft
-- @tparam table  nq   Module nft_queue
-- @tparam table  o    Options
-- @treturn number Octets par ligne
measure_alloc = (wnft, nq, o) ->
  responses = o.alloc_responses
  lines_per_response = o.lines
  line_of = nq.build_line or build_line_fallback
  lines = {}
  seq = 0
  for r = 1, responses
    corr = corr_of r
    widx = r % 2
    for k = 1, lines_per_response
      addr = ADDRS[(k - 1) % #ADDRS + 1]
      kind = (k % 2 == 1) and "ip4" or "mac4"
      key  = (kind == "ip4") and CLIENT or MAC
      seq += 1
      lines[#lines + 1] = line_of kind, key, addr, RULE_ID, TIMEOUT, corr, seq, widx

  cache = wnft.new_cache!
  pending = {}
  ack_queue = {}

  collectgarbage "collect"
  collectgarbage "collect"
  collectgarbage "stop"
  before = collectgarbage "count"
  for r = 1, responses
    base = (r - 1) * lines_per_response
    pending_count = 0
    for k = 1, lines_per_response
      items = wnft.parse_line lines[base + k]
      if items
        -- Une ligne = un seq ; elle peut porter plusieurs adresses (ici une
        -- seule par ligne, format historique, pour rester comparable).
        first = items[1]
        ack_queue[#ack_queue + 1] = { widx: first.widx, seq: first.seq, corr: first.corr, rule_id: first.rule_id }
        for item in *items
          pending_count += 1 if wnft.try_add_pending pending, item, cache
    if pending_count > 0 or #ack_queue > 0
      wnft.flush_batch pending, ack_queue, {}, cache
  after = collectgarbage "count"
  collectgarbage "restart"
  collectgarbage "collect"
  math.max(0, after - before) * 1024 / (responses * lines_per_response)

-- ── CLI ───────────────────────────────────────────────────────────────

--- Parse les arguments.
-- @tparam table argv Arguments (sans nom de programme)
-- @treturn table Options
parse_args = (argv) ->
  o = {
    qps: 500
    turns: { 1, 8 }
    lines: 16
    duration: 10
    idle: 2
    repeat: 3
    alloc: false
    cpu: true
    legacy_gc: false
    alloc_responses: 20000
    tag: "run"
    gc_pause: nil
    gc_stepmul: nil
    gc_idle_step: nil
    gc_max_heap_mb: nil
  }
  i = 1
  next_val = ->
    i += 1
    argv[i]
  while i <= #argv
    switch argv[i]
      when "--qps" then o.qps = tonumber next_val!
      when "--turns"
        o.turns = {}
        for t in (next_val!)\gmatch "[^,]+"
          o.turns[#o.turns + 1] = tonumber t
      when "--lines" then o.lines = tonumber next_val!
      when "--duration" then o.duration = tonumber next_val!
      when "--idle" then o.idle = tonumber next_val!
      when "--repeat" then o.repeat = tonumber next_val!
      when "--alloc" then o.alloc = true
      when "--no-cpu" then o.cpu = false
      when "--legacy-gc" then o.legacy_gc = true
      when "--alloc-responses" then o.alloc_responses = tonumber next_val!
      when "--tag" then o.tag = next_val!
      when "--gc-pause" then o.gc_pause = tonumber next_val!
      when "--gc-stepmul" then o.gc_stepmul = tonumber next_val!
      when "--gc-idle-step" then o.gc_idle_step = tonumber next_val!
      when "--gc-max-heap" then o.gc_max_heap_mb = tonumber next_val!
    i += 1
  o

--- Formate un pourcentage avec une décimale.
-- @tparam number v Valeur
-- @treturn string
fmt1 = (v) -> string.format "%.1f", v

--- Exécute le banc, écrit le rapport, renvoie les lignes.
-- @tparam table argv Arguments
-- @treturn table Lignes du rapport
main = (argv) ->
  o = parse_args argv
  os.execute "mkdir -p #{OUT_DIR}"
  setup_config!

  gc_values = apply_gc o

  install_nft_stub!
  nq = require "nft_queue"
  wnft = require "worker_nft"

  hz = clock_ticks!
  lines = {}
  lines[#lines + 1] = "# Banc CPU worker nft — #{os.date "%Y-%m-%dT%H:%M:%S"}"
  lines[#lines + 1] = ""
  lines[#lines + 1] = "- LuaJIT #{jit.version} / #{jit.arch} / #{jit.os}, #{cpu_count!} processeurs, HZ=#{hz}"
  lines[#lines + 1] = string.format(
    "- GC appliqué avant fork : pause=%d, stepmul=%d, idle_step=%d, max_heap_mb=%d",
    gc_values.pause or 0, gc_values.stepmul or 0,
    gc_values.idle_step or 0, gc_values.max_heap_mb or 0)
  lines[#lines + 1] = string.format(
    "- débit : %s réponses/s × %d lignes/réponse ; %s s de charge + %s s de temps mort ; %s répétition(s)",
    o.qps, o.lines, o.duration, o.idle, o.repeat)
  lines[#lines + 1] = "- `nft.run_cmd` remplacé par un stub (`true`) : coût libnftables exclu, identique entre versions comparées"
  lines[#lines + 1] = ""

  if o.cpu
    lines[#lines + 1] = "| tours | rép. | réponses | durées (s) | CPU charge (s) | CPU charge % | µs CPU/ligne | CPU temps mort % |"
    lines[#lines + 1] = "|---|---|---|---|---|---|---|---|"
    samples = {}
    for turns in *o.turns
      samples[turns] = {}
      for rep = 1, o.repeat
        r = measure_once wnft, nq, o, turns, hz
        cpu_pct = if r.feed_wall > 0 then 100 * r.feed_cpu_s / r.feed_wall else 0
        idle_pct = if o.idle > 0 then 100 * r.idle_cpu_s / o.idle else 0
        us_line = if r.sent > 0 then r.feed_cpu_s * 1e6 / (r.sent * o.lines) else 0
        lines[#lines + 1] = string.format(
          "| %d | %d | %d | %.2f | %.3f | %s | %s | %s |",
          turns, rep, r.sent, r.feed_wall, r.feed_cpu_s, fmt1(cpu_pct), fmt1(us_line), fmt1(idle_pct))
        samples[turns][#samples[turns] + 1] = {
          :us_line, :cpu_pct, :idle_pct, sent: r.sent, wall: r.feed_wall
        }

    -- Médiane, pas minimum : sur ce banc la dispersion vient de la phase du GC
    -- (pas de rafale d'interférence externe à écarter), et le minimum d'un
    -- petit nombre de passages est un estimateur biaisé vers le bas.
    best = {}
    for turns in *o.turns
      list = samples[turns]
      continue unless #list > 0
      table.sort list, (a, b) -> a.us_line < b.us_line
      best[turns] = list[math.max(1, math.ceil(#list / 2))]

    lines[#lines + 1] = ""
    lines[#lines + 1] = "Médiane par taille de tour :"
    lines[#lines + 1] = ""
    lines[#lines + 1] = "| tours | réponses/s | tours/s | µs CPU/ligne | CPU charge % | CPU temps mort % |"
    lines[#lines + 1] = "|---|---|---|---|---|---|"
    for turns in *o.turns
      b = best[turns]
      continue unless b
      turns_per_s = if b.wall > 0 then b.sent / turns / b.wall else 0
      lines[#lines + 1] = string.format(
        "| %d | %s | %s | %s | %s | %s |",
        turns, fmt1(o.qps), fmt1(turns_per_s), fmt1(b.us_line), fmt1(b.cpu_pct), fmt1(b.idle_pct))

    -- Coût d'un tour, dérivé de deux tailles de tour à débit de lignes constant :
    -- CPU/s = a·lignes/s + b·tours/s ⇒ b = ΔCPU/s / Δtours/s.
    if #o.turns >= 2
      t1, t8 = o.turns[1], o.turns[2]
      b1, b8 = best[t1], best[t8]
      if b1 and b8 and b1.wall > 0 and b8.wall > 0
        turns1 = b1.sent / t1 / b1.wall
        turns8 = b8.sent / t8 / b8.wall
        d_cpu = b1.cpu_pct / 100 - b8.cpu_pct / 100
        d_turns = turns1 - turns8
        if d_turns > 0
          lines[#lines + 1] = ""
          lines[#lines + 1] = string.format(
            "Coût d'un tour dérivé (%d vs %d tours) : **%s µs CPU/tour** (ΔCPU %s points, Δ%s tours/s).",
            t1, t8, fmt1(d_cpu / d_turns * 1e6), fmt1((b1.cpu_pct - b8.cpu_pct)), fmt1(d_turns))

  if o.alloc
    alloc = measure_alloc wnft, nq, o
    lines[#lines + 1] = ""
    lines[#lines + 1] = string.format(
      "Allocation du chemin worker nft (parse + pending + flush, GC arrêté, %d réponses) : **%s octets/ligne**.",
      o.alloc_responses, fmt1(alloc))

  out_path = "#{OUT_DIR}/#{o.tag}.md"
  fh = io.open out_path, "w"
  if fh
    fh\write table.concat(lines, "\n") .. "\n"
    fh\close!
  text = table.concat(lines, "\n") .. "\n"
  io.write text
  io.write "\n[nftcpu] rapport : #{out_path}\n"
  lines

{ :main, :parse_args, :build_turn, :build_line_fallback, :corr_of, :stat_cpu_ticks,
  :apply_gc, :install_nft_stub, :measure_alloc, :measure_once, :feed, :setup_config,
  :CLIENT, :MAC, :RULE_ID, :TIMEOUT, :ADDRS, :write_all }
