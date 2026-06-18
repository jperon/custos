-- tests/unit/webui/devices_handler_spec.moon
-- Tests de webui/handlers/devices : liste des appareils + enregistrement MAC.

{ :read_config, :write_config } = require "webui.serializer"
{
  :handle_devices_get, :handle_devices_post
  :read_devices, :mac_name_index, :valid_mac, :events_dir_for
} = require "webui.handlers.devices"

CFG_PATH    = "tmp/devices_handler_spec.lua"
EVENTS_DIR  = "tmp/devices_handler_spec_events"
DEV_FILE    = "#{EVENTS_DIR}/recent-devices.tsv"

write_cfg = (cfg) ->
  ok, err = write_config cfg, CFG_PATH
  assert ok, err

-- state avec reload neutralisé (pas de SIGHUP en test unitaire).
make_state = -> { config_path: CFG_PATH, events_dir: EVENTS_DIR, reload: -> }

make_req = (method, body) ->
  { method: method, path: "", headers: {}, body: body or "" }

write_devices_file = (content) ->
  os.execute "mkdir -p '#{EVENTS_DIR}'"
  fh = assert io.open DEV_FILE, "w"
  fh\write content
  fh\close!

base_cfg = -> { filter: { macs: {}, rules: {} }, events: { dir: EVENTS_DIR } }

describe "webui/handlers/devices", ->

  before_each -> write_cfg base_cfg!
  after_each ->
    os.remove CFG_PATH
    os.remove DEV_FILE

  describe "read_devices", ->

    it "renvoie {} si le fichier est absent", ->
      os.remove DEV_FILE
      assert.same {}, read_devices EVENTS_DIR

    it "ignore une ligne malformée (sans MAC)", ->
      write_devices_file "\tx\ty\n10:00\tip\tu\tq\tallow\t1\t100\t200\n"
      devs = read_devices EVENTS_DIR
      assert.equals 1, #devs
      assert.equals "10:00", devs[1].mac

    it "parse chaque ligne TSV en record", ->
      write_devices_file "aa:bb\t10.0.0.1\tbob\tx.com\tallow\t4\t100\t200\n"
      devs = read_devices EVENTS_DIR
      assert.equals 1, #devs
      assert.equals "aa:bb", devs[1].mac
      assert.equals "10.0.0.1", devs[1].ip
      assert.equals "bob", devs[1].user
      assert.equals "x.com", devs[1].qname
      assert.equals "allow", devs[1].decision
      assert.equals 4, devs[1].count
      assert.equals 200, devs[1].last_ts

  describe "mac_name_index", ->

    it "indexe les valeurs string (contrat actuel)", ->
      idx = mac_name_index { filter: { macs: { peron: "AA:BB:CC:DD:EE:FF" } } }
      assert.equals "peron", idx["aa:bb:cc:dd:ee:ff"]

    it "indexe les valeurs table (configs héritées)", ->
      idx = mac_name_index { filter: { macs: { profs: { "AA:BB", "11:22" } } } }
      assert.equals "profs", idx["aa:bb"]
      assert.equals "profs", idx["11:22"]

  describe "valid_mac", ->

    it "accepte une MAC bien formée", ->
      assert.truthy valid_mac "aa:bb:cc:dd:ee:ff"

    it "rejette une MAC invalide", ->
      assert.is_nil valid_mac "pas-une-mac"
      assert.is_nil valid_mac "aa:bb:cc"

  describe "events_dir_for", ->

    it "priorise state.events_dir", ->
      assert.equals "/x", events_dir_for { events_dir: "/x" }, { events: { dir: "/y" } }

    it "repli sur cfg.events.dir puis défaut", ->
      assert.equals "/y", events_dir_for {}, { events: { dir: "/y" } }
      assert.equals "/tmp/custos/events", events_dir_for {}, {}

  describe "handle_devices_get", ->

    it "retourne 200 avec HTML", ->
      write_devices_file "aa:bb\t10.0.0.1\tbob\tx.com\tallow\t1\t100\t200\n"
      status, hdrs, body = handle_devices_get make_req("GET"), make_state!
      assert.equals 200, status
      assert.truthy body\find("<html", 1, true)
      assert.truthy body\find("aa:bb", 1, true)

    it "montre un formulaire d'enregistrement pour une MAC inconnue", ->
      write_devices_file "aa:bb:cc:dd:ee:ff\t10.0.0.1\t-\tx.com\tallow\t1\t100\t200\n"
      _, _, body = handle_devices_get make_req("GET"), make_state!
      assert.truthy body\find('name="name"', 1, true)

    it "pré-remplit le champ pour une MAC déjà enregistrée (édition)", ->
      write_cfg { filter: { macs: { peron: "aa:bb:cc:dd:ee:ff" }, rules: {} } }
      write_devices_file "aa:bb:cc:dd:ee:ff\t10.0.0.1\t-\tx.com\tallow\t1\t100\t200\n"
      _, _, body = handle_devices_get make_req("GET"), make_state!
      assert.truthy body\find('value="peron"', 1, true)

    it "retourne 500 si config_path invalide", ->
      status = handle_devices_get make_req("GET"), { config_path: "/nonexistent.lua", events_dir: EVENTS_DIR }
      assert.equals 500, status

    it "échappe le HTML des champs (anti-injection)", ->
      write_devices_file "aa:bb\t10.0.0.1\t-\t<script>x\tallow\t1\t100\t200\n"
      _, _, body = handle_devices_get make_req("GET"), make_state!
      assert.is_nil body\find("<script>x", 1, true)
      assert.truthy body\find("&lt;script&gt;x", 1, true)

  describe "handle_devices_post", ->

    it "enregistre la MAC sous le nom dans filter.macs (valeur string)", ->
      body = "mac=AA%3ABB%3ACC%3ADD%3AEE%3AFF&name=peron"
      status, hdrs = handle_devices_post make_req("POST", body), make_state!
      assert.equals 302, status
      assert.truthy hdrs["Location"]\find("devices", 1, true)
      loaded = read_config CFG_PATH
      assert.equals "aa:bb:cc:dd:ee:ff", loaded.filter.macs.peron

    it "renomme une MAC existante (supprime l'ancien nom)", ->
      write_cfg { filter: { macs: { peron: "aa:bb:cc:dd:ee:ff" }, rules: {} } }
      body = "mac=AA%3ABB%3ACC%3ADD%3AEE%3AFF&name=poste1"
      status = handle_devices_post make_req("POST", body), make_state!
      assert.equals 302, status
      loaded = read_config CFG_PATH
      assert.equals "aa:bb:cc:dd:ee:ff", loaded.filter.macs.poste1
      assert.is_nil loaded.filter.macs.peron

    it "retourne 500 si config_path invalide", ->
      state = { config_path: "/nonexistent.lua", events_dir: EVENTS_DIR, reload: -> }
      body = "mac=aa%3Abb%3Acc%3Add%3Aee%3Aff&name=peron"
      status = handle_devices_post make_req("POST", body), state
      assert.equals 500, status

    it "rejette une MAC invalide (400)", ->
      status = handle_devices_post make_req("POST", "mac=nope&name=x"), make_state!
      assert.equals 400, status

    it "rejette un nom vide (400)", ->
      body = "mac=aa%3Abb%3Acc%3Add%3Aee%3Aff&name=+"
      status = handle_devices_post make_req("POST", body), make_state!
      assert.equals 400, status

    it "déclenche le reload après écriture", ->
      reloaded = false
      state = { config_path: CFG_PATH, events_dir: EVENTS_DIR, reload: -> reloaded = true }
      body = "mac=aa%3Abb%3Acc%3Add%3Aee%3Aff&name=poste1"
      handle_devices_post make_req("POST", body), state
      assert.is_true reloaded
