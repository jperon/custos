-- tests/unit/webui/verdicts_handler_spec.moon
-- Tests de webui/handlers/verdicts : lecture de recent-verdicts.tsv et rendu HTML.

{ :write_config } = require "webui.serializer"
{ :handle_verdicts_get, :read_verdicts } = require "webui.handlers.verdicts"

CFG_PATH   = "tmp/verdicts_handler_spec.lua"
EVENTS_DIR = "tmp/verdicts_handler_spec_events"
VFILE      = "#{EVENTS_DIR}/recent-verdicts.tsv"

-- Format recent-verdicts.tsv :
--   mac\tip\tuser\tqname\tdecision\treason\tcount\tfirst_ts\tlast_ts
vline = (mac, ip, user, qname, decision, reason, count, first_ts, last_ts) ->
  "#{mac}\t#{ip}\t#{user}\t#{qname}\t#{decision}\t#{reason}\t#{count}\t#{first_ts}\t#{last_ts}\n"

write_cfg = (cfg) ->
  ok, err = write_config cfg, CFG_PATH
  assert ok, err

make_state = -> { config_path: CFG_PATH, events_dir: EVENTS_DIR }
make_req   = -> { method: "GET", path: "", headers: {} }

write_file = (content) ->
  os.execute "mkdir -p '#{EVENTS_DIR}'"
  fh = assert io.open VFILE, "w"
  fh\write content
  fh\close!

base_cfg = -> { filter: { macs: {}, rules: {} }, events: { dir: EVENTS_DIR } }

describe "webui/handlers/verdicts", ->

  before_each -> write_cfg base_cfg!
  after_each ->
    os.remove CFG_PATH
    os.remove VFILE

  describe "read_verdicts", ->

    it "renvoie {} si le fichier est absent", ->
      os.remove VFILE
      assert.same {}, read_verdicts EVENTS_DIR

    it "ignore une ligne malformée (sans MAC)", ->
      write_file "\tx\ty\n" .. vline "aa:bb", "ip", "u", "q", "block", "r", 1, 100, 200
      vs = read_verdicts EVENTS_DIR
      assert.equals 1, #vs
      assert.equals "aa:bb", vs[1].mac

    it "parse chaque ligne TSV (allow et block) en record", ->
      write_file (vline "aa:bb", "10.0.0.1", "bob", "ads.com", "block", "blocklist", 3, 100, 200) ..
        (vline "cc:dd", "10.0.0.2", "-", "ok.com", "allow", "", 1, 150, 150)
      vs = read_verdicts EVENTS_DIR
      assert.equals 2, #vs
      assert.equals "ads.com", vs[1].qname
      assert.equals "block", vs[1].decision
      assert.equals "blocklist", vs[1].reason
      assert.equals 3, vs[1].count
      assert.equals 200, vs[1].last_ts
      assert.equals "allow", vs[2].decision

  describe "handle_verdicts_get", ->

    it "retourne 200 avec HTML et les en-têtes du tableau", ->
      write_file vline "aa:bb", "10.0.0.1", "bob", "ads.com", "block", "blocklist", 1, 100, 200
      status, hdrs, body = handle_verdicts_get make_req!, make_state!
      assert.equals 200, status
      assert.truthy body\find("<html", 1, true)
      assert.truthy body\find("Domaine", 1, true)
      assert.truthy body\find("Décision", 1, true)
      assert.truthy body\find("ads.com", 1, true)

    it "échappe le HTML des champs (anti-injection)", ->
      write_file vline "aa:bb", "10.0.0.1", "-", "<script>x", "block", "r", 1, 100, 200
      _, _, body = handle_verdicts_get make_req!, make_state!
      assert.is_nil body\find("<script>x", 1, true)
      assert.truthy body\find("&lt;script&gt;x", 1, true)

    it "table vide si events_dir absent (fichier manquant)", ->
      os.remove VFILE
      status, _, body = handle_verdicts_get make_req!, make_state!
      assert.equals 200, status
      assert.truthy body\find("Verdicts récents", 1, true)

    it "retourne 500 si config_path invalide", ->
      status = handle_verdicts_get make_req!, { config_path: "/nonexistent.lua", events_dir: EVENTS_DIR }
      assert.equals 500, status
