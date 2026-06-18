-- src/worker_events.moon
-- Worker d'agrégation des événements DNS.
--
-- Reçoit des lignes TSV depuis worker_questions via le pipe events_rfd :
--   ts<TAB>decision<TAB>qname<TAB>mac_src<TAB>src_ip<TAB>dst_ip<TAB>vlan<TAB>user
--     <TAB>af<TAB>reason<TAB>rule
--
-- Agrège les événements identiques (même clé = les 12 champs sans ts)
-- et les écrit dans des fichiers TSV horaires dans events_dir.
--
-- Flush en TSV au changement d'heure (détecté après chaque retour de poll)
-- ou sur SIGTERM. Les fichiers TSV des heures passées sont compressés avec
-- zstd, puis purgés selon deux critères configurables :
--   • Âge   : suppression des .tsv.zst plus anciens que max_age_hours.
--   • Espace : suppression des plus anciens jusqu'à ce que l'espace libre
--              repasse au-dessus de min_free_pct % du filesystem.

{ :ffi, :libc } = require "ffi_defs"
{ :log_info, :log_warn, :set_action_prefix } = require "log"

bit = require "bit"

-- ── Constantes ──────────────────────────────────────────────────

{ :O_NONBLOCK, :O_APPEND, :O_CREAT, :O_EXCL, :SIG_BLOCK } = require "lib.os_constants"

POLLIN       = 1
POLL_TIMEOUT = 60000   -- ms : garantit la détection des changements d'heure
SIGTERM      = 15
READ_BUF     = 65536   -- octets, buffer de lecture du pipe
O_WRONLY     = 1
FILE_MODE    = 420     -- 0644 décimal

-- Header TSV (écrit une seule fois à la création du fichier via O_EXCL)
HEADER = "decision\tqname\tmac_src\tsrc_ip\tdst_ip\tvlan\tuser\taf\treason\trule\tcount\tfirst_ts\tlast_ts\n"

-- Ring buffer « verdicts » des derniers verdicts DNS (allow ET block), exposé en
-- temps réel au worker AUTH en plus des TSV horaires agrégés. Source unique de :
--   • /refusals (portail captif)    → filtre decision == "block" + MAC du client
--   • /admin/config/devices         → agrégation par MAC (un appareil par ligne)
--   • /admin/config/verdicts        → liste brute (une ligne par verdict)
-- Dédup LRU sur (mac, qname, decision) : un verdict répété n'est gardé qu'une
-- fois (le plus récent), avec un compteur (rate-limiting d'affichage). Écrit
-- dans events_dir.
VERDICTS_MAX          = 8192            -- nombre max d'entrées conservées
VERDICTS_FILE         = "recent-verdicts.tsv"
VERDICTS_MIN_INTERVAL = 5              -- secondes : throttle minimal entre flushes

-- Buffer de lecture partagé (alloué une seule fois au chargement du module)
_read_buf = ffi.new "uint8_t[?]", READ_BUF

-- ── Fonctions ────────────────────────────────────────────────────

--- Retourne l'heure courante sous forme "YYYY-MM-DD-HH".
-- @treturn string Heure courante formatée (ex : "2024-07-15-14")
current_hour = ->
  os.date "%Y-%m-%d-%H"

--- Crée un signalfd non-bloquant écoutant SIGTERM.
-- Le signal est masqué via sigprocmask pour éviter toute livraison asynchrone.
-- @treturn number fd du signalfd
-- @raise string si signalfd échoue
create_signal_fd = ->
  mask = ffi.new "sigset_t_custos"
  ffi.fill mask, ffi.sizeof(mask), 0

  word = ffi.cast "uint32_t*", mask
  word[0] = bit.bor word[0], bit.lshift(1, SIGTERM - 1)

  libc.sigprocmask SIG_BLOCK, mask, nil

  fd = libc.signalfd -1, mask, O_NONBLOCK
  error "signalfd() échoué" if fd < 0
  fd

--- Lit jusqu'à READ_BUF octets depuis fd.
-- N'est appelée qu'après que poll a signalé POLLIN sur le fd.
-- @tparam number fd  Descripteur de fichier à lire
-- @treturn string|nil  Données lues (string non vide), chaîne vide si EAGAIN,
--                      nil si EOF (write-end du pipe fermé)
read_chunk = (fd) ->
  n = libc.read fd, _read_buf, READ_BUF
  if n > 0
    ffi.string _read_buf, n
  elseif n == 0
    nil    -- EOF : extrémité écriture du pipe fermée
  else
    ""     -- EAGAIN ou erreur transitoire

--- Parse une ligne TSV entrante, met à jour la table d'agrégation et, si fourni,
-- le ring buffer des verdicts récents.
-- Format attendu : ts<TAB>key (où key contient 10 champs séparés par TAB).
-- La clé d'agrégation est tout ce qui suit le premier TAB.
-- @tparam string line     Ligne TSV sans le \n final
-- @tparam table  agg      Table d'agrégation { key → {count, first_ts, last_ts} }
-- @tparam ?table verdicts Ring buffer des verdicts (optionnel)
-- @treturn boolean        true si une entrée verdict a été notée
--- Met à jour le ring buffer des verdicts récents pour un verdict DNS.
-- Accepte allow ET block. Dédup LRU sur (mac, qname, decision) : une entrée déjà
-- présente est incrémentée (compteur), ses champs ip/user/reason/last_ts mis à
-- jour et remontée en tête (plus récent d'abord) ; sinon insérée en tête, le
-- buffer étant tronqué à VERDICTS_MAX. Ignore les MAC vides/inconnues.
-- @tparam table  verdicts Ring buffer { {mac, qname, decision, ip, user, reason,
--                         count, first_ts, last_ts}, … }
-- @tparam string decision "allow" ou "block"
-- @tparam string qname    Domaine demandé
-- @tparam string mac      MAC du client
-- @tparam string ip       IP source
-- @tparam string user     Utilisateur authentifié (ou "-"/"")
-- @tparam string reason   Raison textuelle du verdict
-- @tparam string ts       Timestamp (chaîne) du verdict
-- @treturn boolean        true si une entrée a été notée
note_verdict = (verdicts, decision, qname, mac, ip, user, reason, ts) ->
  return false unless mac and qname and mac ~= "" and qname ~= "" and mac ~= "unknown"

  -- Recherche d'une entrée existante (même mac + qname + decision) à remonter.
  for i = 1, #verdicts
    e = verdicts[i]
    if e.mac == mac and e.qname == qname and e.decision == decision
      e.count  += 1
      e.last_ts = ts
      e.ip      = ip
      e.user    = user
      e.reason  = reason
      table.remove verdicts, i
      table.insert verdicts, 1, e
      return true

  table.insert verdicts, 1, {
    :mac, :qname, :decision, :ip, :user, :reason, count: 1, first_ts: ts, last_ts: ts
  }
  verdicts[VERDICTS_MAX + 1] = nil if #verdicts > VERDICTS_MAX
  true

--- Écrit atomiquement le fichier recent-verdicts.tsv (temp + rename).
-- Une ligne par entrée :
--   mac\tip\tuser\tqname\tdecision\treason\tcount\tfirst_ts\tlast_ts.
-- @tparam table  verdicts   Ring buffer des verdicts récents
-- @tparam string events_dir Répertoire de sortie
-- @treturn nil
flush_verdicts = (verdicts, events_dir) ->
  path = "#{events_dir}/#{VERDICTS_FILE}"
  tmp  = "#{path}.tmp"
  fh, err = io.open tmp, "w"
  unless fh
    log_warn -> { action: "verdicts_open_failed", path: tmp, err: err }
    return
  parts = {}
  for e in *verdicts
    parts[#parts + 1] = "#{e.mac}\t#{e.ip or ""}\t#{e.user or ""}\t#{e.qname}\t#{e.decision or ""}\t#{e.reason or ""}\t#{e.count}\t#{e.first_ts}\t#{e.last_ts}\n"
  fh\write table.concat parts
  fh\close!
  os.rename tmp, path

process_line = (line, agg, verdicts) ->
  tab_pos = line\find "\t"
  return false unless tab_pos

  ts_str = line\sub 1, tab_pos - 1
  key    = line\sub tab_pos + 1
  return false if key == ""

  entry = agg[key]
  if entry
    entry.count  += 1
    entry.last_ts = ts_str
  else
    agg[key] = { count: 1, first_ts: ts_str, last_ts: ts_str }

  -- Champs détaillés : nécessaires au ring buffer des verdicts. On ne parse
  -- qu'une fois, et seulement si le buffer est demandé.
  return false unless verdicts
  -- key = decision \t qname \t mac_src \t src_ip \t dst_ip \t vlan \t user \t af \t reason \t rule
  decision, qname, mac, src_ip, _dst_ip, _vlan, user, _af, reason = key\match(
    "^([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)")
  return false unless decision

  note_verdict verdicts, decision, qname, mac, src_ip, user, reason, ts_str

--- Écrit le fichier TSV d'agrégation pour l'heure donnée.
-- Utilise O_EXCL pour détecter si le fichier est nouveau et écrire le header,
-- puis O_APPEND pour ajouter les lignes de données. Skip si agg est vide.
-- @tparam table  agg        Table d'agrégation { key → {count, first_ts, last_ts} }
-- @tparam string hour       Heure courante "YYYY-MM-DD-HH"
-- @tparam string events_dir Répertoire de sortie des fichiers TSV
-- @treturn nil
flush_to_file = (agg, hour, events_dir) ->
  -- Skip si la table est vide
  has_entries = false
  for _ in pairs agg
    has_entries = true
    break
  return unless has_entries

  path = "#{events_dir}/events-#{hour}.tsv"

  -- Tentative de création exclusive : réussit uniquement si le fichier est nouveau
  fd_excl = libc.open path, bit.bor(O_WRONLY, O_CREAT, O_EXCL), FILE_MODE
  if fd_excl >= 0
    libc.write fd_excl, HEADER, #HEADER
    libc.close fd_excl

  -- Ouverture en append pour les lignes de données
  fd = libc.open path, bit.bor(O_WRONLY, O_CREAT, O_APPEND), FILE_MODE
  if fd < 0
    errno = tonumber(ffi.C.__errno_location()[0])
    log_warn -> { action: "open_failed", path: path, errno: errno }
    return

  for key, entry in pairs agg
    line = "#{key}\t#{entry.count}\t#{entry.first_ts}\t#{entry.last_ts}\n"
    libc.write fd, line, #line

  libc.close fd

--- Compresse les fichiers events-*.tsv anciens (hors heure courante).
-- Utilise find via io.popen pour lister les candidats, puis zstd --rm
-- pour chaque fichier exclu du slot courant.
-- @tparam string events_dir       Répertoire des fichiers d'événements
-- @tparam string current_hour_str Heure courante "YYYY-MM-DD-HH" (fichier exclu)
-- @treturn nil
compress_old = (events_dir, current_hour_str) ->
  current_file = "events-#{current_hour_str}.tsv"
  fh = io.popen "find '#{events_dir}' -maxdepth 1 -name 'events-*.tsv' -type f"
  return unless fh
  for path in fh\lines!
    fname = path\match "([^/]+)$"
    if fname and fname ~= current_file
      os.execute "zstd -q --rm '#{path}'"
  fh\close!

--- Retourne le pourcentage d'espace libre sur le filesystem contenant path.
-- Utilise `df -k` via io.popen (compatible BusyBox / OpenWrt).
-- @tparam  string path  Chemin situé sur le filesystem à sonder
-- @treturn number|nil   Pourcentage libre (0–100), ou nil en cas d'erreur
free_pct_on = (path) ->
  fh = io.popen "df -k '#{path}' 2>/dev/null | tail -1"
  return nil unless fh
  line = fh\read "*l"
  fh\close!
  return nil unless line
  -- Le use% est le seul token contenant "%" sur la ligne
  use_str = line\match "(%d+)%%"
  return nil unless use_str
  use = tonumber use_str
  return nil unless use
  100 - use

--- Extrait l'âge en heures d'un fichier events-YYYY-MM-DD-HH.tsv.zst.
-- @tparam  string fname  Nom de fichier (sans chemin)
-- @treturn number|nil    Âge en heures depuis l'heure encodée, ou nil si non parseable
file_age_hours = (fname) ->
  y, mo, d, h = fname\match "^events%-(%d%d%d%d)%-(%d%d)%-(%d%d)%-(%d%d)%.tsv%.zst$"
  return nil unless y
  file_epoch = os.time { year: tonumber(y), month: tonumber(mo), day: tonumber(d),
                         hour: tonumber(h), min: 0, sec: 0 }
  (os.time! - file_epoch) / 3600

--- Supprime les fichiers .tsv.zst trop anciens ou quand l'espace libre est insuffisant.
-- Parcourt les fichiers en ordre chronologique (tri alphabétique du nom = tri temporel).
-- Étape 1 : supprime ceux dont l'âge dépasse max_age_hours.
-- Étape 2 : si l'espace libre est encore sous min_free_pct, supprime les plus
--           anciens restants jusqu'au rétablissement du seuil.
-- @tparam string events_dir     Répertoire des fichiers d'événements
-- @tparam number max_age_hours  Âge maximum avant suppression (heures)
-- @tparam number min_free_pct   Seuil d'espace libre minimum (%)
-- @treturn nil
cleanup_old = (events_dir, max_age_hours, min_free_pct) ->
  fh = io.popen "find '#{events_dir}' -maxdepth 1 -name 'events-*.tsv.zst' -type f 2>/dev/null"
  return unless fh
  files = [path for path in fh\lines!]
  fh\close!
  return if #files == 0

  table.sort files   -- ordre alphabétique = ordre chronologique (format YYYY-MM-DD-HH)

  -- Étape 1 : suppression par âge
  for path in *files
    fname = path\match "([^/]+)$"
    age   = file_age_hours fname
    if age and age > max_age_hours
      os.remove path
      log_info -> { action: "events_cleanup_age", file: fname, age_h: math.floor age }

  -- Étape 2 : suppression par espace libre (recharge la liste après étape 1)
  free = free_pct_on events_dir
  return unless free and free < min_free_pct

  fh2 = io.popen "find '#{events_dir}' -maxdepth 1 -name 'events-*.tsv.zst' -type f 2>/dev/null"
  return unless fh2
  remaining = [path for path in fh2\lines!]
  fh2\close!
  table.sort remaining

  for path in *remaining
    free = free_pct_on events_dir
    break unless free and free < min_free_pct
    fname = path\match "([^/]+)$"
    os.remove path
    log_info -> { action: "events_cleanup_space", file: fname, free_pct: free }

--- Boucle principale du worker d'agrégation d'événements DNS.
-- Reçoit des lignes TSV via events_rfd, les agrège par heure,
-- et flush en fichier TSV au changement d'heure ou sur SIGTERM.
-- La purge des anciens .tsv.zst est déclenchée au démarrage et à chaque
-- changement d'heure (critères : âge > max_age_hours, espace libre < min_free_pct).
-- @tparam number events_rfd    fd de lecture du pipe events (envoyé par worker_questions)
-- @tparam string events_dir   Répertoire de sortie des fichiers TSV horaires
-- @tparam number max_age_hours Âge maximum des .tsv.zst avant suppression (heures)
-- @tparam number min_free_pct  Seuil d'espace libre minimum avant purge (%)
-- @treturn nil
run = (events_rfd, events_dir, max_age_hours, min_free_pct) ->
  set_action_prefix "events_"
  os.execute "mkdir -p '#{events_dir}'"

  sfd = create_signal_fd!

  pfds = ffi.new "struct pollfd[2]"
  pfds[0].fd     = events_rfd
  pfds[0].events = POLLIN
  pfds[1].fd     = sfd
  pfds[1].events = POLLIN

  agg       = {}
  verdicts  = {}
  last_verdicts_write = 0
  line_buf  = ""
  hour      = current_hour!

  siginfo = ffi.new "signalfd_siginfo"
  sig_sz  = ffi.sizeof "signalfd_siginfo"

  log_info -> { action: "start", events_dir: events_dir, hour: hour,
             max_age_hours: max_age_hours, min_free_pct: min_free_pct }

  -- Purge initiale au démarrage (utile si events_dir est sur stockage persistant)
  cleanup_old events_dir, max_age_hours, min_free_pct

  while true
    libc.poll pfds, 2, POLL_TIMEOUT

    -- Priorité au signal SIGTERM : flush propre puis sortie immédiate
    if bit.band(pfds[1].revents, POLLIN) ~= 0
      libc.read sfd, siginfo, sig_sz
      if siginfo.ssi_signo == SIGTERM
        log_info -> { action: "sigterm", hour: hour }
        flush_to_file agg, hour, events_dir
        flush_verdicts verdicts, events_dir
        libc._exit 0

    -- Lecture des données sur le pipe events
    if bit.band(pfds[0].revents, POLLIN) ~= 0
      chunk = read_chunk events_rfd
      if chunk == nil
        -- EOF : l'extrémité écriture est fermée (worker_questions mort)
        -- Le superviseur va redémarrer question ; le pipe reste ouvert côté superviseur.
        log_warn -> { action: "pipe_eof", fd: events_rfd }
      elseif #chunk > 0
        line_buf ..= chunk
        verdict_touched = false
        -- Découpe line_buf sur les \n et traite chaque ligne complète
        while true
          nl = line_buf\find "\n", 1, true
          break unless nl
          line     = line_buf\sub 1, nl - 1
          line_buf = line_buf\sub nl + 1
          if #line > 0
            verdict_touched = true if process_line line, agg, verdicts
        now = os.time!
        -- Flush throttlé du ring buffer des verdicts (≥ VERDICTS_MIN_INTERVAL)
        if verdict_touched and now - last_verdicts_write >= VERDICTS_MIN_INTERVAL
          flush_verdicts verdicts, events_dir
          last_verdicts_write = now

    -- Détection du changement d'heure après chaque retour de poll
    new_hour = current_hour!
    if new_hour ~= hour
      log_info -> { action: "hour_change", old: hour, new: new_hour }
      flush_to_file agg, hour, events_dir
      compress_old events_dir, new_hour
      cleanup_old events_dir, max_age_hours, min_free_pct
      agg  = {}
      hour = new_hour

{ :run, :process_line, :note_verdict, :flush_verdicts }
