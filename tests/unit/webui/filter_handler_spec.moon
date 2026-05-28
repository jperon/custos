-- tests/unit/webui/filter_handler_spec.moon
-- Tests de webui/handlers/filter : CRUD des dictionnaires nommés.

{ :read_config, :write_config } = require "webui.serializer"
{
  :handle_nets_get,    :handle_nets_post
  :handle_macs_get,    :handle_macs_post
  :handle_users_get,   :handle_users_post
  :handle_times_get,   :handle_times_post
  :handle_decision_get,:handle_decision_post
} = require "webui.handlers.filter"

CFG_PATH = "tmp/filter_handler_spec.lua"

write_cfg = (cfg) ->
  ok, err = write_config cfg, CFG_PATH
  assert ok, err

make_state = ->
  { config_path: CFG_PATH }

make_req = (method, body) ->
  { method: method, path: "", headers: {}, body: body or "" }

base_cfg = ->
  {
    filter: {
      nets:  {}
      macs:  {}
      users: {}
      times: {}
      decision: { first_match_wins: true, continue_to_next_rule: false }
      rules: {}
    }
  }

describe "webui/handlers/filter", ->

  before_each ->
    write_cfg base_cfg!

  after_each ->
    os.remove CFG_PATH

  -- ── Nets GET ─────────────────────────────────────────────────────────────

  describe "handle_nets_get", ->

    it "retourne 200 avec HTML", ->
      status, hdrs, body = handle_nets_get make_req("GET"), make_state!
      assert.equals 200, status
      assert.truthy body\find("<html", 1, true)

    it "affiche les réseaux existants", ->
      write_cfg { filter: { nets: { local: { "192.168.0.0/16", "10.0.0.0/8" } } } }
      _, _, body = handle_nets_get make_req("GET"), make_state!
      assert.truthy body\find("local", 1, true)

    it "retourne 500 si config_path invalide", ->
      state = { config_path: "/nonexistent/file.lua" }
      status, _, _ = handle_nets_get make_req("GET"), state
      assert.equals 500, status

  -- ── Nets POST — ajout ────────────────────────────────────────────────────

  describe "handle_nets_post — ajout", ->

    it "ajoute un réseau et redirige", ->
      body_str = "action=save&newkey=local&newval=192.168.0.0%2F16%0A10.0.0.0%2F8"
      status, hdrs, _ = handle_nets_post make_req("POST", body_str), make_state!
      assert.equals 302, status
      assert.truthy hdrs["Location"]\find("nets", 1, true)

    it "le réseau est bien persisté", ->
      body_str = "action=save&newkey=wan&newval=203.0.113.0%2F24"
      handle_nets_post make_req("POST", body_str), make_state!
      loaded = (read_config CFG_PATH)
      assert.not_nil loaded.filter.nets.wan

    it "ignore les ajouts avec newkey vide", ->
      body_str = "action=save&newkey=+&newval=1.2.3.0%2F24"
      handle_nets_post make_req("POST", body_str), make_state!
      loaded = (read_config CFG_PATH)
      -- la clé " " (espace) ne doit pas être ajoutée
      found = false
      if loaded.filter.nets
        for k in pairs loaded.filter.nets
          found = true if k\match "%S"
      assert.is_false found

  -- ── Nets POST — suppression ───────────────────────────────────────────────

  describe "handle_nets_post — suppression", ->

    it "supprime une entrée existante", ->
      write_cfg { filter: { nets: { local: { "192.168.0.0/16" } }, rules: {} } }
      body_str = "delete=local"
      handle_nets_post make_req("POST", body_str), make_state!
      loaded = (read_config CFG_PATH)
      assert.is_nil loaded.filter.nets.local

    it "redirige après suppression", ->
      write_cfg { filter: { nets: { x: { "1.0.0.0/8" } }, rules: {} } }
      body_str = "delete=x"
      status, hdrs, _ = handle_nets_post make_req("POST", body_str), make_state!
      assert.equals 302, status

  -- ── Users POST ────────────────────────────────────────────────────────────

  describe "handle_users_post", ->

    it "ajoute un utilisateur (valeur scalaire, pas liste)", ->
      body_str = "action=save&newkey=alice&newval=alice%40example.com"
      handle_users_post make_req("POST", body_str), make_state!
      loaded = (read_config CFG_PATH)
      assert.equals "alice@example.com", loaded.filter.users.alice

    it "supprime un utilisateur", ->
      write_cfg { filter: { users: { alice: "alice@example.com" }, rules: {} } }
      body_str = "delete=alice"
      handle_users_post make_req("POST", body_str), make_state!
      loaded = (read_config CFG_PATH)
      assert.is_nil loaded.filter.users.alice

  -- ── MACs POST ────────────────────────────────────────────────────────────

  describe "handle_macs_post", ->

    it "ajoute une entrée MAC (liste de valeurs)", ->
      body_str = "action=save&newkey=phones&newval=aa%3Abb%3Acc%3Add%3Aee%3Aff%0A11%3A22%3A33%3A44%3A55%3A66"
      handle_macs_post make_req("POST", body_str), make_state!
      loaded = (read_config CFG_PATH)
      assert.not_nil loaded.filter.macs.phones
      assert.truthy type(loaded.filter.macs.phones) == "table"

  -- ── Times GET/POST ────────────────────────────────────────────────────────

  describe "handle_times_get", ->

    it "retourne 200", ->
      status, _, _ = handle_times_get make_req("GET"), make_state!
      assert.equals 200, status

  describe "handle_times_post", ->

    it "ajoute une plage horaire et persiste", ->
      body_str = "action=save&newkey=matin&newstart=08%3A00&newend=12%3A00"
      handle_times_post make_req("POST", body_str), make_state!
      loaded = (read_config CFG_PATH)
      assert.not_nil loaded.filter.times.matin
      assert.equals "08:00", loaded.filter.times.matin[1]
      assert.equals "12:00", loaded.filter.times.matin[2]

    it "supprime une plage horaire", ->
      write_cfg { filter: { times: { matin: { "08:00", "12:00" } }, rules: {} } }
      body_str = "delete=matin"
      handle_times_post make_req("POST", body_str), make_state!
      loaded = (read_config CFG_PATH)
      assert.is_nil loaded.filter.times.matin

  -- ── Decision GET/POST ─────────────────────────────────────────────────────

  describe "handle_decision_get", ->

    it "retourne 200 avec HTML", ->
      status, _, body = handle_decision_get make_req("GET"), make_state!
      assert.equals 200, status
      assert.truthy body\find("first-match", 1, true) or body\find("cision", 1, true)

  describe "handle_decision_post", ->

    it "enregistre first_match_wins=true", ->
      body_str = "fmw=1&fmw_present=1&ctn_present=1"
      handle_decision_post make_req("POST", body_str), make_state!
      loaded = (read_config CFG_PATH)
      assert.is_true loaded.filter.decision.first_match_wins

    it "enregistre first_match_wins=false si absent du form", ->
      body_str = "fmw_present=1&ctn_present=1"
      handle_decision_post make_req("POST", body_str), make_state!
      loaded = (read_config CFG_PATH)
      assert.is_false loaded.filter.decision.first_match_wins

    it "enregistre continue_to_next_rule=true", ->
      body_str = "fmw=1&fmw_present=1&ctn=1&ctn_present=1"
      handle_decision_post make_req("POST", body_str), make_state!
      loaded = (read_config CFG_PATH)
      assert.is_true loaded.filter.decision.continue_to_next_rule

    it "redirige après POST", ->
      body_str = "fmw=1&fmw_present=1&ctn_present=1"
      status, hdrs, _ = handle_decision_post make_req("POST", body_str), make_state!
      assert.equals 302, status
      assert.truthy hdrs["Location"]\find("decision", 1, true)
