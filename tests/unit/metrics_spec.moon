-- tests/unit/metrics_spec.moon
-- Tests des compteurs par règle et de l'export JSON périodique (src/metrics.moon).

json = require "lib.json"
{
  :init
  :record_verdict
  :get_metrics_json
  :write_now
  :purge_files
  :flush_if_due
  :maybe_flush
  :file_path
  :clear
  :_get_state
} = require "metrics"

DIR = "tmp/metrics_spec"
FILE = "#{DIR}/metrics-w0.json"

list_dir = ->
  h = io.popen "ls -1 '#{DIR}' 2>/dev/null"
  out = {}
  for name in h\lines!
    out[#out + 1] = name
  h\close!
  out

clean_dir = ->
  for name in *list_dir!
    os.remove "#{DIR}/#{name}"
  os.remove DIR

file_exists = ->
  fh = io.open FILE, "r"
  return false unless fh
  fh\close!
  true

read_snapshot = ->
  fh = assert io.open FILE, "r"
  content = fh\read "*a"
  fh\close!
  json.decode content

describe "metrics", ->

  before_each ->
    clean_dir!
    os.execute "mkdir -p '#{DIR}'"
    init { enabled: true, flush_interval: 60 }, {}
    clear!

  after_each ->
    init { enabled: true }, {}
    clear!
    clean_dir!

  describe "record_verdict", ->

    it "initialise le compteur d'une nouvelle règle", ->
      record_verdict "rule1", "allow"
      state = _get_state!
      assert.is_not_nil state["rule1"]
      assert.equals 1, state["rule1"].allow_count

    it "incrémente allow/refuse/dnsonly", ->
      for i = 1, 3
        record_verdict "rule1", "allow"
      record_verdict "rule1", "refuse"
      record_verdict "rule1", "refuse"
      record_verdict "rule1", "dnsonly"
      state = _get_state!
      assert.equals 3, state["rule1"].allow_count
      assert.equals 2, state["rule1"].refuse_count
      assert.equals 1, state["rule1"].dnsonly_count

    it "gère plusieurs règles", ->
      record_verdict "rule1", "allow"
      record_verdict "rule2", "refuse"
      record_verdict "rule1", "allow"
      state = _get_state!
      assert.equals 2, state["rule1"].allow_count
      assert.equals 1, state["rule2"].refuse_count

    it "ignore nil et un verdict inconnu", ->
      record_verdict nil, "allow"
      record_verdict "rule1", nil
      record_verdict "rule1", "invalid"
      state = _get_state!
      assert.equals 0, #state
      assert.equals 0, state["rule1"].allow_count + state["rule1"].refuse_count + state["rule1"].dnsonly_count

  describe "get_metrics_json", ->

    it "exporte timestamp et compteurs par règle", ->
      record_verdict "rule1", "allow"
      record_verdict "rule1", "allow"
      record_verdict "rule1", "refuse"
      snap = get_metrics_json!
      assert.equals "number", type snap.timestamp
      assert.equals 1, #snap.rules
      assert.equals "rule1", snap.rules[1].rule_id
      assert.equals 2, snap.rules[1].verdicts.allow
      assert.equals 1, snap.rules[1].verdicts.refuse
      assert.equals 0, snap.rules[1].verdicts.dnsonly

    it "exporte une liste vide sans donnée", ->
      assert.same {}, get_metrics_json!.rules

    it "n'exporte rien quand désactivé", ->
      init { enabled: false }
      record_verdict "rule1", "allow"
      assert.same {}, get_metrics_json!.rules

  describe "export périodique", ->

    it "n'écrit rien avant l'intervalle, puis un instantané", ->
      now = 0
      init { enabled: true, flush_interval: 10 },
        { dir: DIR, name: "w0", clock: (-> now), check_every: 1 }
      record_verdict "r1", "allow"

      now = 0
      maybe_flush!
      assert.is_false file_exists!

      now = 9
      maybe_flush!
      assert.is_false file_exists!

      now = 10
      maybe_flush!
      snap = read_snapshot!
      assert.equals 10, snap.timestamp
      assert.equals "r1", snap.rules[1].rule_id
      assert.equals 1, snap.rules[1].verdicts.allow

    it "consulte l'horloge seulement tous les check_every paquets", ->
      now = 0
      clock_calls = 0
      fake_clock = ->
        clock_calls += 1
        now
      init { enabled: true, flush_interval: 10 },
        { dir: DIR, name: "w0", clock: fake_clock, check_every: 4 }
      for i = 1, 3
        maybe_flush!
      assert.equals 0, clock_calls
      maybe_flush!  -- 4e paquet : lecture d'horloge
      assert.equals 1, clock_calls

    it "utilise check_every = 32 par défaut", ->
      clock_calls = 0
      fake_clock = ->
        clock_calls += 1
        0
      init { enabled: true, flush_interval: 10 },
        { dir: DIR, name: "w0", clock: fake_clock }
      for i = 1, 31
        maybe_flush!
      assert.equals 0, clock_calls
      maybe_flush!  -- 32e paquet
      assert.equals 1, clock_calls

    it "flush_if_due écrit sur le seul passage temporel", ->
      now = 0
      init { enabled: true, flush_interval: 10 },
        { dir: DIR, name: "w0", clock: (-> now) }
      record_verdict "r1", "allow"
      assert.is_true write_now!  -- instantané initial
      now = 9
      assert.is_false flush_if_due!
      now = 10
      assert.is_true flush_if_due!
      snap = read_snapshot!
      assert.equals 1, snap.rules[1].verdicts.allow

    it "write_now produit un instantané vide valide au démarrage", ->
      init { enabled: true }, { dir: DIR, name: "w0" }
      assert.is_true write_now!
      snap = read_snapshot!
      assert.equals "number", type snap.timestamp
      assert.same {}, snap.rules

    it "n'écrit rien quand désactivé", ->
      now = 1000
      init { enabled: false, flush_interval: 10 },
        { dir: DIR, name: "w0", clock: (-> now), check_every: 1 }
      record_verdict "r1", "allow"
      maybe_flush!
      assert.is_false file_exists!
      assert.is_false write_now!

    it "file_path reflète le nom du worker", ->
      init { enabled: true }, { dir: DIR, name: "dns-q3" }
      assert.equals "#{DIR}/metrics-dns-q3.json", file_path!
      init { enabled: true }, {}
      assert.is_nil file_path!

    it "échoue sans lever si le répertoire cible n'existe pas", ->
      init { enabled: true }, { dir: "#{DIR}/absent", name: "w0" }
      record_verdict "r1", "allow"
      assert.is_false write_now!

  describe "purge_files", ->

    it "supprime instantanés et temporaires, laisse les autres fichiers", ->
      write = (name, content) ->
        fh = assert io.open "#{DIR}/#{name}", "w"
        fh\write content
        fh\close!
      write "metrics-a.json", "{}"
      write "metrics-a.json.tmp.1", "x"
      write "metrics-b.json.tmp.7", "x"
      write "notes.txt", "à conserver"

      assert.equals 3, purge_files DIR
      assert.same { "notes.txt" }, list_dir!
      assert.equals 0, purge_files nil

  describe "atomicité", ->

    it "ne laisse aucun temporaire après une écriture réussie", ->
      init { enabled: true }, { dir: DIR, name: "w0" }
      record_verdict "r1", "allow"
      assert.is_true write_now!
      assert.same { "metrics-w0.json" }, list_dir!

    it "préserve l'ancien fichier si le renommage échoue", ->
      init { enabled: true }, { dir: DIR, name: "w0" }
      record_verdict "r1", "allow"
      assert.is_true write_now!
      snap = read_snapshot!
      assert.equals 1, snap.rules[1].verdicts.allow

      record_verdict "r1", "allow"
      real_rename = os.rename
      renamed_from = nil
      fail_rename = (src, dst) ->
        renamed_from = src
        false
      rawset os, "rename", fail_rename
      ok = write_now!
      rawset os, "rename", real_rename

      assert.is_false ok
      assert.truthy renamed_from and renamed_from\find ".tmp.", 1, true
      -- L'instantané précédent reste intact et complet.
      snap = read_snapshot!
      assert.equals 1, snap.rules[1].verdicts.allow
      assert.same { "metrics-w0.json" }, list_dir!

  describe "mémoire bornée", ->

    it "évince la règle la moins récemment vue au-delà de max_rules", ->
      init { max_rules: 3, enabled: true }
      for i = 1, 4
        record_verdict "rule#{i}", "allow"
      snap = get_metrics_json!
      ids = {}
      for r in *snap.rules
        ids[r.rule_id] = true
      assert.equals 3, #snap.rules
      assert.is_nil ids["rule1"]
      assert.is_true ids["rule4"]

  describe "chargement du module (config.metrics)", ->
    saved_metrics = nil
    saved_config  = nil

    before_each ->
      saved_metrics = package.loaded["metrics"]
      saved_config  = package.loaded["config"]

    after_each ->
      package.loaded["metrics"] = saved_metrics
      package.loaded["config"]  = saved_config

    it "honore metrics.enabled = false dès le chargement", ->
      package.loaded["config"] = { metrics: { enabled: false } }
      package.loaded["metrics"] = nil
      fresh = require "metrics"
      fresh.record_verdict "rule1", "allow"
      assert.equals 0, #fresh.get_metrics_json!.rules

    it "reste actif quand metrics.enabled est absent", ->
      package.loaded["config"] = {}
      package.loaded["metrics"] = nil
      fresh = require "metrics"
      fresh.record_verdict "rule1", "allow"
      assert.equals 1, #fresh.get_metrics_json!.rules

    it "reste actif quand metrics.enabled = true", ->
      package.loaded["config"] = { metrics: { enabled: true } }
      package.loaded["metrics"] = nil
      fresh = require "metrics"
      fresh.record_verdict "rule1", "allow"
      assert.equals 1, #fresh.get_metrics_json!.rules
