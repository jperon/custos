-- tests/unit/webui/metrics_handler_spec.moon
-- Tests de webui/handlers/metrics : agrégation multi-workers, fichiers
-- corrompus/périmés, échappement HTML et état désactivé.

json = require "lib.json"
{ :write_config } = require "webui.serializer"
{ :handle_metrics_get, :read_snapshots, :aggregate, :runtime_dir_for } = require "webui.handlers.metrics"

CFG_PATH = "tmp/metrics_handler_spec_cfg.lua"
DIR      = "tmp/metrics_handler_spec_dir"
NOW      = 1700000000

write_cfg = (cfg) ->
  ok, err = write_config cfg, CFG_PATH
  assert ok, err

clean_dir = ->
  h = io.popen "ls -1 '#{DIR}' 2>/dev/null"
  names = {}
  for name in h\lines!
    names[#names + 1] = name
  h\close!
  for name in *names
    os.remove "#{DIR}/#{name}"
  os.remove DIR

write_snap = (name, content) ->
  os.execute "mkdir -p '#{DIR}'"
  fh = assert io.open "#{DIR}/#{name}", "w"
  fh\write content
  fh\close!

rule = (id, allow, refuse, dnsonly) ->
  { rule_id: id, verdicts: { :allow, :refuse, :dnsonly } }

snap_json = (ts, rules) ->
  json.encode { timestamp: ts, rules: rules }

make_state = (over) ->
  s = { config_path: CFG_PATH, runtime_dir: DIR, now: NOW }
  if over
    for k, v in pairs over
      s[k] = v
  s

make_req = -> { method: "GET", path: "/admin/metrics", headers: {}, body: "", query: {} }

enabled_cfg = -> { metrics: { enabled: true, flush_interval: 60 } }

describe "webui/handlers/metrics", ->

  before_each ->
    clean_dir!
    os.execute "mkdir -p '#{DIR}'"
    write_cfg enabled_cfg!

  after_each ->
    clean_dir!
    os.remove CFG_PATH

  describe "read_snapshots", ->

    it "renvoie une liste vide sans répertoire", ->
      os.remove DIR
      snaps, ignored = read_snapshots DIR
      assert.same {}, snaps
      assert.equals 0, ignored

    it "ignore un fichier corrompu sans lever", ->
      write_snap "metrics-a.json", (snap_json NOW, { (rule "r1", 1, 0, 0) })
      write_snap "metrics-b.json", "{ pas du json"
      snaps, ignored = read_snapshots DIR
      assert.equals 1, #snaps
      assert.equals 1, ignored

    it "ignore un horodatage ou une forme invalides", ->
      write_snap "metrics-ts.json", (json.encode { timestamp: 0, rules: {} })
      write_snap "metrics-shape.json", (json.encode { timestamp: NOW, rules: "x" })
      write_snap "metrics-ok.json", (snap_json NOW, {})
      snaps, ignored = read_snapshots DIR
      assert.equals 1, #snaps
      assert.equals 2, ignored

  describe "runtime_dir_for", ->

    it "privilégie state.runtime_dir", ->
      assert.equals "/x", runtime_dir_for({ runtime_dir: "/x" }, {})

    it "replie sur le répertoire du pidfile", ->
      assert.equals "tmp/run", runtime_dir_for {}, { runtime: { pid_file: "tmp/run/custos.pid" } }
      assert.equals ".", runtime_dir_for {}, { runtime: { pid_file: "custos.pid" } }

  describe "aggregate", ->

    it "somme les compteurs de plusieurs workers par règle", ->
      snaps = {
        { name: "metrics-dns-q0.json", timestamp: NOW, rules: {
          (rule "r1", 2, 1, 0)
          (rule "r2", 0, 3, 0)
        } }
        { name: "metrics-dns-q1.json", timestamp: NOW, rules: {
          (rule "r1", 5, 0, 1)
        } }
      }
      agg = aggregate snaps
      assert.equals 7, agg.totals.allow
      assert.equals 4, agg.totals.refuse
      assert.equals 1, agg.totals.dnsonly
      assert.equals 12, agg.total
      -- r1 total 9, r2 total 3 : tri décroissant.
      assert.equals "r1", agg.rules[1].rule_id
      assert.equals 7, agg.rules[1].allow
      assert.equals 1, agg.rules[1].dnsonly
      assert.equals "r2", agg.rules[2].rule_id

    it "ignore les compteurs négatifs ou non numériques", ->
      agg = aggregate {
        { name: "x", timestamp: NOW, rules: {
          { rule_id: "r1", verdicts: { allow: -5, refuse: "x", dnsonly: 2 } }
          { rule_id: "huge", verdicts: { allow: 1e300, refuse: 0, dnsonly: 0 } }
          { rule_id: "bad" }
          "pas une règle"
        } }
      }
      assert.equals 0, agg.totals.allow
      assert.equals 0, agg.totals.refuse
      assert.equals 2, agg.totals.dnsonly

  describe "handle_metrics_get", ->

    it "agrège deux workers et affiche totaux, verdicts et règles", ->
      write_snap "metrics-dns-q0.json", (snap_json NOW, { (rule "r1", 2, 0, 0) })
      write_snap "metrics-dns-q1.json", (snap_json NOW, { (rule "r1", 3, 1, 0) })
      status, hdrs, body = handle_metrics_get make_req!, make_state!
      assert.equals 200, status
      assert.equals "text/html; charset=UTF-8", hdrs["Content-Type"]
      assert.truthy body\find("<html", 1, true)
      assert.truthy body\find("Totaux", 1, true)
      assert.truthy body\find("Autorisés (allow)", 1, true)
      assert.truthy body\find("Total verdicts", 1, true)
      assert.truthy body\find("metrics-dns-q0.json", 1, true)
      assert.truthy body\find("metrics-dns-q1.json", 1, true)
      -- r1 : 5 allow, 1 refuse, 0 dnsonly, total 6.
      assert.truthy body\find("r1", 1, true)
      assert.truthy body\find("<td>6</td>", 1, true)

    it "ignore un fichier corrompu et le signale", ->
      write_snap "metrics-a.json", (snap_json NOW, { (rule "ok", 1, 0, 0) })
      write_snap "metrics-b.json", "{{{"
      status, _, body = handle_metrics_get make_req!, make_state!
      assert.equals 200, status
      assert.truthy body\find("1 fichier(s) illisible(s) ou corrompu(s)", 1, true)
      assert.truthy body\find("ok", 1, true)

    it "ignore un instantané périmé dans les totaux mais affiche sa fraîcheur", ->
      write_snap "metrics-old.json", (snap_json (NOW - 5000), { (rule "old", 9, 0, 0) })
      write_snap "metrics-new.json", (snap_json NOW, { (rule "new", 1, 0, 0) })
      status, _, body = handle_metrics_get make_req!, make_state!
      assert.equals 200, status
      assert.truthy body\find("périmé (ignoré)", 1, true)
      assert.truthy body\find("à jour", 1, true)
      -- Le total ne compte que le worker à jour (1 allow) : le 9 du périmé
      -- n'apparaît dans aucune cellule de compteur.
      assert.truthy body\find("<td>1</td>", 1, true)
      assert.is_nil body\find("<td>9</td>", 1, true)

    it "échappe le HTML des noms de règle et de worker", ->
      write_snap "metrics-x.json", (snap_json NOW, { (rule "<script>alert(1)</script>", 1, 0, 0) })
      _, _, body = handle_metrics_get make_req!, make_state!
      assert.is_nil body\find("<script>alert(1)</script>", 1, true)
      assert.truthy body\find("&lt;script&gt;alert(1)&lt;/script&gt;", 1, true)

    it "indique que les métriques sont désactivées", ->
      write_cfg { metrics: { enabled: false } }
      write_snap "metrics-a.json", (snap_json NOW, { (rule "r1", 1, 0, 0) })
      status, _, body = handle_metrics_get make_req!, make_state!
      assert.equals 200, status
      assert.truthy body\find("désactivées", 1, true)
      assert.truthy body\find("metrics.enabled = false", 1, true)

    it "rend 200 même si le répertoire d'instantanés n'existe pas", ->
      os.remove DIR
      status, _, body = handle_metrics_get make_req!, make_state!
      assert.equals 200, status
      assert.truthy body\find("Aucun instantané de worker trouvé", 1, true)
