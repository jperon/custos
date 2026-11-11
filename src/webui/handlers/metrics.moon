-- src/webui/handlers/metrics.moon
-- GET /admin/metrics — lecture seule.
-- Agrège les instantanés JSON écrits par chaque worker_questions
-- (<runtime>/metrics-<worker>.json, cf. src/metrics.moon) : totaux, répartition
-- par verdict et par règle. Les fichiers d'une exécution précédente sont purgés
-- par le superviseur au démarrage ; un fichier illisible ou corrompu est ignoré
-- sans erreur. L'âge de chaque instantané est affiché à titre d'information.

H = require "auth.html"
{ :page } = require "webui.handlers.dashboard"
{ :read_config } = require "webui.serializer"
{ :esc } = require "webui.util"
json = require "lib.json"
pidfile = require "lib.pidfile"
{ :shquote } = require "lib.shquote"

-- Au-delà de 3 intervalles de flush (minimum 180 s), l'instantané est signalé
-- comme sans activité récente — il reste compté dans les totaux.
IDLE_FACTOR = 3
IDLE_MIN    = 180

--- Répertoire d'exécution (celui du pidfile, cf. src/doh/query.moon).
-- @tparam table state État webui (runtime_dir injectable pour les tests)
-- @tparam table cfg   Config chargée
-- @treturn string Répertoire des instantanés
runtime_dir_for = (state, cfg) ->
  return state.runtime_dir if state.runtime_dir
  pid_path = pidfile.resolve_path cfg and cfg.runtime and cfg.runtime.pid_file
  pid_path\match("^(.*)/") or "."

--- Compteur non négatif entier, sinon 0 (fichier corrompu = zéro).
counter = (v) ->
  n = tonumber v
  return 0 unless n and n >= 0 and n <= 1e15 and n == math.floor(n)
  n

--- Vrai si la table décodée a la forme d'un instantané valide.
-- @tparam any snap Valeur décodée
-- @treturn boolean
valid_snapshot = (snap) ->
  return false unless type(snap) == "table"
  return false unless type(snap.timestamp) == "number"
  return false unless snap.timestamp > 0 and snap.timestamp < 4102444800
  type(snap.rules) == "table"

--- Liste les fichiers d'instantanés et décode ceux qui sont valides.
-- @tparam string dir Répertoire des instantanés
-- @treturn table Instantanés { {name, timestamp, rules}, … }
-- @treturn number Nombre de fichiers illisibles ou corrompus (ignorés)
read_snapshots = (dir) ->
  h = io.popen "ls -1 #{shquote(dir)}/metrics-*.json 2>/dev/null"
  return {}, 0 unless h
  out = {}
  ignored = 0
  for path in h\lines!
    fh = io.open path, "r"
    unless fh
      ignored += 1
      continue
    content = fh\read "*a"
    fh\close!
    snap = nil
    ok = pcall -> snap = json.decode content
    unless ok and valid_snapshot snap
      ignored += 1
      continue
    name = path\match "([^/]+)$" or path
    out[#out + 1] = { :name, timestamp: snap.timestamp, rules: snap.rules }
  h\close!
  out, ignored

total_of = (e) -> e.allow + e.refuse + e.dnsonly

--- Vrai si une entrée de règle a la forme attendue.
-- @tparam any r Entrée décodée
-- @treturn boolean
valid_rule = (r) ->
  type(r) == "table" and type(r.rule_id) == "string" and type(r.verdicts) == "table"

--- Somme les compteurs de tous les instantanés, par verdict et par règle.
-- @tparam table snapshots Instantanés valides
-- @treturn table { totals = {allow, refuse, dnsonly}, rules = {…}, total }
aggregate = (snapshots) ->
  totals = { allow: 0, refuse: 0, dnsonly: 0 }
  by_rule = {}
  order = {}
  for snap in *snapshots
    for r in *snap.rules
      continue unless valid_rule r
      entry = by_rule[r.rule_id]
      unless entry
        entry = { rule_id: r.rule_id, allow: 0, refuse: 0, dnsonly: 0 }
        by_rule[r.rule_id] = entry
        order[#order + 1] = entry
      for key in *{ "allow", "refuse", "dnsonly" }
        n = counter r.verdicts[key]
        entry[key] += n
        totals[key] += n
  table.sort order, (a, b) ->
    ta, tb = total_of(a), total_of(b)
    if ta != tb
      ta > tb
    else
      a.rule_id < b.rule_id
  { :totals, rules: order, total: total_of totals }

--- Date lisible, ou mention neutre pour un horodatage invalide.
-- @tparam number ts Horodatage Unix
-- @treturn string
fmt_ts = (ts) ->
  ok, s = pcall os.date, "%Y-%m-%d %H:%M:%S", ts
  ok and s or "date inconnue"

render_workers = (snapshots, now, idle_after) ->
  rows = {}
  for snap in *snapshots
    age   = math.max 0, now - snap.timestamp
    idle  = age > idle_after
    state = if idle then "aucune activité depuis #{age} s" else "à jour"
    rows[#rows + 1] = H.tr {
      H.td (esc snap.name)
      H.td (esc fmt_ts snap.timestamp)
      H.td "#{age} s"
      H.td (esc state)
    }
  if #rows == 0
    H.p { style: "color:#555" }, "Aucun instantané de worker trouvé."
  else
    H.table {
      H.thead {
        H.tr { H.th "Worker", H.th "Dernier instantané", H.th "Âge", H.th "État" }
      }
      H.tbody {}, table.concat rows
    }

render_totals = (agg) ->
  H.table {
    H.thead { H.tr { H.th "Verdict", H.th "Total" } }
    H.tbody {}, table.concat {
      H.tr { H.td "Autorisés (allow)", H.td tostring agg.totals.allow }
      H.tr { H.td "Refusés (refuse)", H.td tostring agg.totals.refuse }
      H.tr { H.td "DNS seul (dnsonly)", H.td tostring agg.totals.dnsonly }
      H.tr { H.td (H.strong "Total verdicts"), H.td (H.strong tostring agg.total) }
    }
  }

render_rules = (agg) ->
  rows = {}
  for r in *agg.rules
    rows[#rows + 1] = H.tr {
      H.td (esc r.rule_id)
      H.td tostring r.allow
      H.td tostring r.refuse
      H.td tostring r.dnsonly
      H.td tostring total_of(r)
    }
  if #rows == 0
    H.p { style: "color:#555" }, "Aucun verdict enregistré pour l'instant."
  else
    H.table {
      H.thead {
        H.tr { H.th "Règle", H.th "Allow", H.th "Refuse", H.th "DNS only", H.th "Total" }
      }
      H.tbody {}, table.concat rows
    }

handle_metrics_get = (req, state) ->
  cfg, err = read_config state.config_path
  return 500, {}, "Erreur config : #{err}" unless cfg
  cfg_metrics = cfg.metrics or {}
  enabled = cfg_metrics.enabled != false
  now = state.now or os.time!
  dir = runtime_dir_for state, cfg

  if not enabled
    body = H.section {
      H.h2 "Métriques"
      H.p "Métriques désactivées (metrics.enabled = false) : aucun instantané n'est écrit par les workers."
    }
    return 200, { ["Content-Type"]: "text/html; charset=UTF-8" }, page "Métriques", body

  snapshots, ignored = read_snapshots dir
  interval = tonumber cfg_metrics.flush_interval or 60
  idle_after = math.max interval * IDLE_FACTOR, IDLE_MIN
  agg = aggregate snapshots

  notices = {}
  notices[#notices + 1] = H.p { style: "color:#555" },
    "Instantanés lus dans #{esc dir} ; tous les instantanés valides sont comptés, les fichiers illisibles ou corrompus sont ignorés."
  if ignored > 0
    notices[#notices + 1] = H.p { style: "color:#a00" },
      "#{ignored} fichier(s) illisible(s) ou corrompu(s) ignoré(s)."

  parts = {}
  parts[#parts + 1] = H.section {
    H.h2 "Totaux"
    table.concat notices
    render_totals agg
  }
  parts[#parts + 1] = H.section {
    H.h2 "Par règle"
    render_rules agg
  }
  parts[#parts + 1] = H.section {
    H.h2 "Workers"
    render_workers snapshots, now, idle_after
    " "
    H.a { class: "btn btn-secondary", href: "/admin/" }, "Retour"
  }
  body = table.concat parts

  200, { ["Content-Type"]: "text/html; charset=UTF-8" }, page "Métriques", body

{
  :handle_metrics_get
  :runtime_dir_for
  :read_snapshots
  :aggregate
}
