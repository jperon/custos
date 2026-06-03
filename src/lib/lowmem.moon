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

{ :LOWMEM_THRESHOLD_DEFAULT_KB, :read_mem_total_kb, :parse_queues, :detect, :collapse_nfqueue }
