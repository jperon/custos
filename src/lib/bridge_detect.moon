-- src/lib/bridge_detect.moon
-- Détection robuste de l'interface bridge du système.
--
-- L'ancienne détection s'appuyait sur `ip -brief link show type bridge`, non
-- supporté par le busybox d'OpenWrt (cf. src/main.moon : même raison pour les
-- esclaves). Quand la commande échoue, on retombait silencieusement sur "br0",
-- alors que le bridge réel peut s'appeler "br-lan" → filtre HS.
--
-- Détection via sysfs (/sys/class/net/<name>/bridge), busybox-compatible. En
-- cas de bridges multiples, on choisit celui qui a le plus de ports esclaves
-- (/sys/class/net/<name>/brif/) ; départage : br-lan > br0 > ordre alphabétique.

DEFAULT_IFNAME = "br0"

-- Lit les lignes d'une commande shell ; renvoie {} en cas d'échec.
read_lines = (cmd, popen) ->
  popen or= io.popen
  handle = popen cmd
  return {} unless handle
  out = {}
  for line in handle\lines!
    name = line\match "^%s*(%S+)"
    out[#out + 1] = name if name
  handle\close!
  out

--- Énumère les interfaces bridge du système.
-- @tparam ?function popen io.popen injectable (tests)
-- @treturn table liste des noms de bridge (peut être vide)
list_bridges = (popen) ->
  out = {}
  -- sysfs : un bridge expose /sys/class/net/<name>/bridge. Fiable sur busybox.
  for path in *read_lines "ls -d /sys/class/net/*/bridge 2>/dev/null", popen
    name = path\match "/sys/class/net/([^/]+)/bridge"
    out[#out + 1] = name if name
  return out if #out > 0
  -- Repli iproute2 complet (systèmes non-busybox).
  read_lines "ip -brief link show type bridge 2>/dev/null", popen

--- Compte les ports esclaves d'un bridge.
-- @tparam string name nom du bridge
-- @tparam ?function popen io.popen injectable (tests)
-- @treturn number nombre de ports esclaves
count_slaves = (name, popen) ->
  #read_lines "ls -1 /sys/class/net/#{name}/brif/ 2>/dev/null", popen

-- Score de départage déterministe (plus haut = préféré) en cas d'égalité de
-- nombre d'esclaves : br-lan > br0 > autres (l'ordre alpha tranche le reste).
tiebreak_rank = (name) ->
  return 2 if name == "br-lan"
  return 1 if name == DEFAULT_IFNAME
  0

--- Choisit le bridge avec le plus d'esclaves (fonction pure, cœur testable).
-- @tparam table names liste de noms de bridge
-- @tparam ?function count_fn fonction nom→nb d'esclaves (défaut count_slaves)
-- @treturn string|nil bridge choisi, ou nil si liste vide
pick_bridge = (names, count_fn) ->
  return nil if not names or #names == 0
  count_fn or= count_slaves
  best, best_slaves, best_rank = nil, -1, -1
  -- Tri stable par ordre alphabétique pour un départage final déterministe.
  sorted = [n for n in *names]
  table.sort sorted
  for name in *sorted
    slaves = count_fn name
    rank = tiebreak_rank name
    if slaves > best_slaves or (slaves == best_slaves and rank > best_rank)
      best, best_slaves, best_rank = name, slaves, rank
  best

--- Vrai si <name> ressemble à un nom d'interface réseau Linux valide.
-- Garde-fou contre une valeur de config corrompue (ex. "Warning:" écrit par
-- une ancienne détection busybox). IFNAMSIZ = 16 → 15 caractères utiles ;
-- pas d'espace, ni '/', ni ':'.
-- @tparam ?string name
-- @treturn boolean
valid_name = (name) ->
  return false unless name and #name > 0 and #name <= 15
  not not name\match "^[%w%.%-_]+$"

--- Vrai si l'interface réseau <name> existe (sysfs).
-- @tparam string name nom d'interface
-- @treturn boolean
exists = (name) ->
  return false unless name and #name > 0
  fh = io.open "/sys/class/net/#{name}/operstate", "r"
  if fh
    fh\close!
    return true
  -- Repli : le répertoire de l'interface lui-même.
  fh2 = io.open "/sys/class/net/#{name}/ifindex", "r"
  if fh2
    fh2\close!
    return true
  false

--- Détecte l'interface bridge à utiliser.
-- Priorité : env BRIDGE_IFNAME → détection sysfs (plus d'esclaves) → "br0".
-- @tparam ?table opts { popen, count_fn } injectables (tests)
-- @treturn string nom de l'interface bridge
detect = (opts) ->
  opts or= {}
  env = os.getenv "BRIDGE_IFNAME"
  if env and #env > 0
    return env if valid_name env
    io.stderr\write "bridge_detect: BRIDGE_IFNAME invalide ignoré: #{env}\n"

  pick_bridge(list_bridges(opts.popen), opts.count_fn) or DEFAULT_IFNAME

{ :DEFAULT_IFNAME, :list_bridges, :count_slaves, :pick_bridge, :valid_name, :exists, :detect }
