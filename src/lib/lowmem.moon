-- src/lib/lowmem.moon
-- Détection du mode « RAM faible » et réduction des files NFQUEUE.
--
-- Sur les machines très contraintes (< 128 Mo par défaut), un seul worker par
-- file NFQUEUE suffit : le débit parallèle compte moins que l'empreinte
-- mémoire. Ce module centralise (a) la lecture de la RAM totale, (b) la
-- décision lowmem (forçable via config.runtime), et (c) la réduction de chaque
-- plage de files à une seule queue. Logique pure et testable, sans effet de
-- bord autre que la lecture de /proc/meminfo (chemin paramétrable).

LOWMEM_THRESHOLD_DEFAULT_KB = 131072  -- 128 Mo

-- Borne de la table `pending` d'un worker réponses (cf. `ipc.pending_max`).
-- 20 000 ≈ 16 Mo par worker réponses dans le pire cas (afflux de questions sans
-- réponse, ≈ 0,84 Ko/entrée) ; le profil RAM faible vise ~4 Mo par worker.
-- Recommandation mesurée : docs/agents/perf.md §15.5.
PENDING_MAX_DEFAULT = 20000
LOWMEM_PENDING_MAX  = 5000

--- Lit MemTotal (en kB) depuis /proc/meminfo.
-- @tparam[opt] string path Chemin du fichier (défaut "/proc/meminfo")
-- @treturn number kilo-octets de RAM totale (0 si illisible)
read_mem_total_kb = (path = "/proc/meminfo") ->
  f = io.open path, "r"
  return 0 unless f
  total = 0
  for line in f\lines!
    kb = line\match "^MemTotal:%s+(%d+)"
    if kb
      total = tonumber(kb) or 0
      break
  f\close!
  total

--- Parse une liste de files NFQUEUE : nombres et plages ("0,2,5-7,10-12").
-- @tparam string str Spécification de files
-- @treturn table Liste des numéros de file (1-indexée)
parse_queues = (str) ->
  queues = {}
  return queues unless str
  for part in str\gmatch "%d+%-?%d*"
    if part\match "%-%d+"
      a, b = part\match "(%d+)%-(%d+)"
      a, b = tonumber(a), tonumber(b)
      if a and b
        if a <= b
          for n = a, b do table.insert queues, n
        else
          for n = b, a do table.insert queues, n
      else
        n = tonumber part
        table.insert queues, n if n
    else
      n = tonumber part
      table.insert queues, n if n
  queues

--- Vrai si `str` est exploitable telle quelle dans `queue num` par nft :
-- un nombre seul (`"4"`) ou une plage contiguë croissante (`"4-5"`).
-- nft n'accepte QUE ces deux formes (`queue to 4-5`) : une liste avec virgules
-- (`"4,6"`) est une erreur de syntaxe et ferait échouer l'application du
-- ruleset, donc la distribution des files.
-- @tparam string|nil str Spécification de files
-- @treturn boolean
is_contiguous_range = (str) ->
  return false unless type(str) == "string"
  s = str\gsub "%s+", ""
  return true if s\match "^%d+$"
  a, b = s\match "^(%d+)%-(%d+)$"
  return false unless a and b
  tonumber(a) <= tonumber(b)

--- Détermine si l'on doit fonctionner en mode « RAM faible ».
-- `runtime_cfg.lowmem` force la décision (`true`/`"on"`, `false`/`"off"`) ;
-- sinon autodétection selon `runtime_cfg.lowmem_threshold_kb` (défaut 128 Mo).
-- @tparam[opt] table runtime_cfg Section config.runtime
-- @tparam[opt] function mem_reader Lecteur de RAM (défaut read_mem_total_kb)
-- @treturn boolean true si une seule file par règle doit être conservée
detect = (runtime_cfg = {}, mem_reader = read_mem_total_kb) ->
  switch runtime_cfg.lowmem
    when true, "on"   then return true
    when false, "off" then return false
  threshold = tonumber(runtime_cfg.lowmem_threshold_kb) or LOWMEM_THRESHOLD_DEFAULT_KB
  mem_kb = mem_reader!
  mem_kb > 0 and mem_kb < threshold

--- Borne de la table `pending` à appliquer selon le profil.
-- Même logique que `lib.nfq_rcvbuf.resolve_requested` : `configured`
-- (`ipc.pending_max`) prime quand il est >= 1 ; sinon 20 000, ou 5 000 en mode
-- RAM faible (0 ou valeur illisible = auto, cf. doc/CONFIG.md § ipc).
-- @tparam number|string|nil configured Valeur de configuration
-- @tparam boolean is_lowmem Profil RAM faible actif
-- @treturn number Borne effective (entrées)
resolve_pending_max = (configured, is_lowmem) ->
  v = tonumber configured
  return math.floor v if v and v >= 1
  if is_lowmem then LOWMEM_PENDING_MAX else PENDING_MAX_DEFAULT

--- Ramène chaque plage NFQUEUE listée à sa première file (mutation en place).
-- @tparam table nfqueue Section config.nfqueue (mutée)
-- @tparam[opt] table keys Clés à réduire (défaut questions/responses/captive/reject)
-- @treturn table Résumé { clé: "ancien → nouveau" } des files réduites
collapse_nfqueue = (nfqueue, keys = { "questions", "responses", "captive", "reject" }) ->
  collapsed = {}
  for key in *keys
    qs = parse_queues nfqueue[key]
    if #qs > 1
      first = tostring qs[1]
      collapsed[key] = "#{nfqueue[key]} → #{first}"
      nfqueue[key] = first
  collapsed

{ :LOWMEM_THRESHOLD_DEFAULT_KB, :PENDING_MAX_DEFAULT, :LOWMEM_PENDING_MAX,
  :read_mem_total_kb, :parse_queues, :is_contiguous_range, :detect,
  :resolve_pending_max, :collapse_nfqueue }
