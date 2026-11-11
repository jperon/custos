-- tests/unit/webui/audit_handlers_spec.moon
-- Journal d'audit par famille de handler webui : une ligne INFO par
-- modification, un WARN pour un refus, aucune valeur/secret dans les lignes.
--
-- Le module `log` réel est chargé avec un `write` factice qui capture les
-- lignes : on vérifie ainsi ce qui serait réellement écrit vers logread.

ffi = require "ffi"
token = require "auth.token"
{ :write_sessions } = require "auth.sessions"
{ :read_config, :write_config } = require "webui.serializer"

CFG_PATH   = "tmp/audit_handlers_cfg.lua"
LISTS_DIR  = "tmp/audit_handlers_lists"
EVENTS_DIR = "tmp/audit_handlers_events"
SESS_PATH  = "tmp/audit_handlers_sessions.lua"
PID_PATH   = "tmp/audit_handlers.pid"

TEST_KEY  = string.rep "\x42", 32
ADMIN_MAC = "aa:bb:cc:dd:ee:ff"
SECRET    = "AUDIT_SECRET_9f3c7a"

RELOAD_MODULES = {
  "webui.audit"
  "webui.handlers.config"
  "webui.handlers.filter"
  "webui.handlers.rules"
  "webui.handlers.lists"
  "webui.handlers.devices"
  "webui.handlers.system"
  "webui.router"
}

write_cfg = (cfg) ->
  ok, err = write_config cfg, CFG_PATH
  assert ok, err

make_req = (body, user) ->
  {
    method:     "POST"
    path:       ""
    headers:    {}
    body:       body or ""
    admin_user: user or "alice"
    peer_ip:    "192.0.2.10"
  }

make_state = -> { config_path: CFG_PATH }

describe "webui/audit — handlers", ->
  local log, lines
  local h_config, h_filter, h_rules, h_lists, h_devices, h_system, router
  local saved_modules, saved_log, saved_config, saved_ffi_defs

  setup ->
    saved_modules = {}
    for name in *RELOAD_MODULES
      saved_modules[name] = package.loaded[name]
      package.loaded[name] = nil
    saved_log      = package.loaded["log"]
    saved_config   = package.loaded["config"]
    saved_ffi_defs = package.loaded["ffi_defs"]

    lines = {}
    fake_libc = {
      write: (fd, buf, n) ->
        lines[#lines + 1] = ffi.string buf, n
        n
      clock_gettime: (clk, tp) ->
        tp.tv_sec  = 1700000000
        tp.tv_nsec = 0
        0
    }
    package.loaded["ffi_defs"] = { :ffi, libc: fake_libc, libnfq: {}, libnft: {} }
    package.loaded["config"]   = { runtime: { log_level: "INFO" }, filter: { rules: {} } }
    package.loaded["log"]      = nil
    log = require "log"

    require "webui.audit"
    h_config  = require "webui.handlers.config"
    h_filter  = require "webui.handlers.filter"
    h_rules   = require "webui.handlers.rules"
    h_lists   = require "webui.handlers.lists"
    h_devices = require "webui.handlers.devices"
    h_system  = require "webui.handlers.system"
    router    = require "webui.router"

  teardown ->
    for name in *RELOAD_MODULES
      package.loaded[name] = saved_modules[name]
    package.loaded["log"]      = saved_log
    package.loaded["config"]   = saved_config
    package.loaded["ffi_defs"] = saved_ffi_defs

  before_each ->
    log._rl_reset!
    log.set_action_prefix ""
    lines = {}
    os.remove CFG_PATH
    os.remove SESS_PATH
    os.remove PID_PATH
    write_cfg { runtime: { log_level: "INFO" }, auth: {}, filter: { rules: {} } }

  after_each ->
    log.set_action_prefix ""
    os.remove CFG_PATH
    os.remove SESS_PATH
    os.remove PID_PATH

  one_line = (action, level) ->
    level or= "INFO"
    found = [l for l in *lines when l\find(" #{level} ", 1, true) and l\find("action=#{action}", 1, true)]
    assert.equals 1, #found, "attendu 1 ligne #{level} #{action}, obtenu #{#found}"
    found[1]

  no_info = (action) ->
    found = [l for l in *lines when l\find(" INFO ", 1, true) and l\find("action=#{action}", 1, true)]
    assert.equals 0, #found, "aucune ligne INFO #{action} attendue"

  assert_no_secret = ->
    for l in *lines
      assert.is_nil l\find(SECRET, 1, true), "secret présent dans le journal : #{l}"

  -- ── Configuration ───────────────────────────────────────────────────────

  describe "handlers/config", ->

    it "sauvegarde de section : une INFO avec section, user, peer, ok=1", ->
      status = h_config.handle_config_section_post make_req("log_level=WARN&benchmark_present=1"), "runtime", make_state!
      assert.equals 302, status
      line = one_line "webui_config_saved"
      assert.truthy line\find("section=runtime", 1, true)
      assert.truthy line\find("user=alice", 1, true)
      assert.truthy line\find("peer=192.0.2.10", 1, true)
      assert.truthy line\find("ok=1", 1, true)

    it "échec de lecture : une INFO ok=0 err=read_config", ->
      state = { config_path: "tmp/audit_handlers_absent.lua" }
      os.remove state.config_path
      status = h_config.handle_config_section_post make_req("log_level=INFO"), "runtime", state
      assert.equals 500, status
      line = one_line "webui_config_saved"
      assert.truthy line\find("ok=0", 1, true)
      assert.truthy line\find("err=read_config", 1, true)

    it "section inconnue : WARN refused, aucune INFO", ->
      status = h_config.handle_config_section_post make_req("x=1"), "nope", make_state!
      assert.equals 404, status
      no_info "webui_config_saved"
      line = one_line "webui_change_refused", "WARN"
      assert.truthy line\find("reason=unknown_section", 1, true)

    it "ne journalise jamais une valeur de config (secret)", ->
      body = "log_level=INFO&key=#{SECRET}&secrets=#{SECRET}&session_key=#{SECRET}&password=#{SECRET}"
      h_config.handle_config_section_post make_req(body), "auth", make_state!
      one_line "webui_config_saved"
      assert_no_secret!

    it "champs scalaires du filtre : section=filter", ->
      h_config.handle_filter_general_post make_req("safe_search=1&youtube_restrict=moderate"), make_state!
      line = one_line "webui_config_saved"
      assert.truthy line\find("section=filter", 1, true)

    it "dans le worker AUTH (préfixe auth_), l'action est auth_webui_*", ->
      log.set_action_prefix "auth_"
      h_config.handle_config_section_post make_req("log_level=WARN&benchmark_present=1"), "runtime", make_state!
      line = one_line "auth_webui_config_saved"
      assert.truthy line\find("action=auth_webui_config_saved", 1, true)
      assert.equals 0, #([l for l in *lines when l\find("action=webui_config_saved", 1, true)])

  -- ── Règles ──────────────────────────────────────────────────────────────

  describe "handlers/rules", ->

    before_each ->
      write_cfg { filter: { rules: {
        { description: "A", conditions: {}, actions: { "allow" } }
        { description: "B", conditions: {}, actions: { "block" } }
      } } }

    it "création : webui_rule_saved avec le nouvel identifiant", ->
      h_rules.handle_rules_new_post make_req("description=audit&action%5Btype%5D=allow"), make_state!
      line = one_line "webui_rule_saved"
      assert.truthy line\find("rule_id=3", 1, true)

    it "édition : webui_rule_saved avec rule_id", ->
      h_rules.handle_rules_edit_post make_req("description=modifiee&action%5Btype%5D=allow"), 1, make_state!
      line = one_line "webui_rule_saved"
      assert.truthy line\find("rule_id=1", 1, true)

    it "suppression : webui_rule_deleted avec rule_id", ->
      h_rules.handle_rules_delete make_req(""), 1, make_state!
      line = one_line "webui_rule_deleted"
      assert.truthy line\find("rule_id=1", 1, true)

    it "bascule : webui_rule_toggled avec l'état enabled", ->
      h_rules.handle_rules_toggle make_req(""), 1, make_state!
      line = one_line "webui_rule_toggled"
      assert.truthy line\find("rule_id=1", 1, true)
      assert.truthy line\find("enabled=0", 1, true)

    it "déplacement : webui_rule_moved avec rule_id et dir", ->
      h_rules.handle_rules_move make_req("dir=down"), 1, make_state!
      line = one_line "webui_rule_moved"
      assert.truthy line\find("rule_id=1", 1, true)
      assert.truthy line\find("dir=down", 1, true)

    it "réordonnancement : webui_rules_reordered avec le nombre de règles", ->
      h_rules.handle_rules_reorder make_req("order=2,1"), make_state!
      line = one_line "webui_rules_reordered"
      assert.truthy line\find("rules=2", 1, true)

    it "échec règle absente : WARN refused, aucune INFO", ->
      status = h_rules.handle_rules_edit_post make_req("description=x&action%5Btype%5D=allow"), 99, make_state!
      assert.equals 404, status
      no_info "webui_rule_saved"
      line = one_line "webui_change_refused", "WARN"
      assert.truthy line\find("reason=rule_not_found", 1, true)
      assert.truthy line\find("rule_id=99", 1, true)

    it "ordre invalide : WARN refused invalid_order", ->
      status = h_rules.handle_rules_reorder make_req("order=1"), make_state!
      assert.equals 400, status
      no_info "webui_rules_reordered"
      line = one_line "webui_change_refused", "WARN"
      assert.truthy line\find("reason=invalid_order", 1, true)

  -- ── Listes ──────────────────────────────────────────────────────────────

  describe "handlers/lists", ->

    before_each ->
      os.execute "mkdir -p '#{LISTS_DIR}/domain'"
      fh = assert io.open "#{LISTS_DIR}/domain/famille.txt", "w"
      fh\write "example.com\n"
      fh\close!
      write_cfg { filter: { lists_dir: LISTS_DIR, rules: {} } }

    after_each ->
      os.execute "rm -rf '#{LISTS_DIR}'"

    it "enregistrement : webui_list_saved avec type et nom, jamais le contenu", ->
      body = "action=save&content=#{SECRET}.com%0Aautre.com"
      h_lists.handle_list_post make_req(body), "domain", "famille", make_state!
      line = one_line "webui_list_saved"
      assert.truthy line\find("list=domain", 1, true)
      assert.truthy line\find("name=famille", 1, true)
      assert_no_secret!

    it "création : webui_list_saved avec le nom", ->
      h_lists.handle_list_new_post make_req("name=nouvelle&content=x.com"), "domain", make_state!
      line = one_line "webui_list_saved"
      assert.truthy line\find("name=nouvelle", 1, true)

    it "suppression : webui_list_deleted", ->
      h_lists.handle_list_post make_req("action=delete"), "domain", "famille", make_state!
      line = one_line "webui_list_deleted"
      assert.truthy line\find("name=famille", 1, true)

    it "renommage : webui_list_renamed avec ancien et nouveau nom", ->
      h_lists.handle_list_post make_req("action=rename&new_name=autre"), "domain", "famille", make_state!
      line = one_line "webui_list_renamed"
      assert.truthy line\find("name=famille", 1, true)
      assert.truthy line\find("new=autre", 1, true)

    it "conflit de nom : WARN refused list_exists, aucune INFO", ->
      fh = assert io.open "#{LISTS_DIR}/domain/autre.txt", "w"
      fh\write "x\n"
      fh\close!
      status = h_lists.handle_list_post make_req("action=rename&new_name=autre"), "domain", "famille", make_state!
      assert.equals 409, status
      no_info "webui_list_renamed"
      line = one_line "webui_change_refused", "WARN"
      assert.truthy line\find("reason=list_exists", 1, true)

    it "nom invalide : WARN refused invalid_name", ->
      status = h_lists.handle_list_new_post make_req("name=invalid%20name&content=x"), "domain", make_state!
      assert.equals 400, status
      line = one_line "webui_change_refused", "WARN"
      assert.truthy line\find("reason=invalid_name", 1, true)

  -- ── Appareils ───────────────────────────────────────────────────────────

  describe "handlers/devices", ->

    it "enregistrement MAC : webui_device_saved avec mac/name et un reload", ->
      reloaded = 0
      state = { config_path: CFG_PATH, events_dir: EVENTS_DIR, reload: -> reloaded += 1 }
      status = h_devices.handle_devices_post make_req("mac=AA%3ABB%3ACC%3ADD%3AEE%3AFF&name=portable"), state
      assert.equals 302, status
      assert.equals 1, reloaded
      line = one_line "webui_device_saved"
      assert.truthy line\find("mac=aa:bb:cc:dd:ee:ff", 1, true)
      assert.truthy line\find("name=portable", 1, true)

    it "MAC invalide : WARN refused, aucune INFO", ->
      state = { config_path: CFG_PATH, reload: -> }
      status = h_devices.handle_devices_post make_req("mac=zz&name=portable"), state
      assert.equals 400, status
      no_info "webui_device_saved"
      line = one_line "webui_change_refused", "WARN"
      assert.truthy line\find("reason=invalid_mac", 1, true)

    it "échec de lecture config : INFO ok=0 err=read_config", ->
      state = { config_path: "tmp/audit_handlers_absent.lua", reload: -> }
      os.remove state.config_path
      status = h_devices.handle_devices_post make_req("mac=aa%3Abb%3Acc%3Add%3Aee%3Aff&name=x"), state
      assert.equals 500, status
      line = one_line "webui_device_saved"
      assert.truthy line\find("ok=0", 1, true)
      assert.truthy line\find("err=read_config", 1, true)

  -- ── Dictionnaires nommés et décision ───────────────────────────────────

  describe "handlers/filter", ->

    it "réseaux nommés : webui_nets_saved avec section", ->
      h_filter.handle_nets_post make_req("newkey=lan&newval=192.168.0.0%2F16"), make_state!
      line = one_line "webui_nets_saved"
      assert.truthy line\find("section=nets", 1, true)

    it "plages horaires : webui_times_deleted avec le nom", ->
      write_cfg { filter: { times: { matin: { "08:00", "12:00" } }, rules: {} } }
      h_filter.handle_times_post make_req("delete=matin"), make_state!
      line = one_line "webui_times_deleted"
      assert.truthy line\find("name=matin", 1, true)

    it "décision : webui_decision_saved", ->
      h_filter.handle_decision_post make_req("fmw=1"), make_state!
      line = one_line "webui_decision_saved"
      assert.truthy line\find("section=filter.decision", 1, true)

    it "échec de lecture : INFO ok=0 err=read_config", ->
      state = { config_path: "tmp/audit_handlers_absent.lua" }
      os.remove state.config_path
      status = h_filter.handle_nets_post make_req("newkey=lan&newval=x"), state
      assert.equals 500, status
      line = one_line "webui_nets_saved"
      assert.truthy line\find("ok=0", 1, true)
      assert.truthy line\find("err=read_config", 1, true)

  -- ── Rechargement ────────────────────────────────────────────────────────

  describe "handlers/system — reload", ->

    it "succès : webui_reload_requested avec le PID superviseur", ->
      require("lib.pidfile").write 4242, PID_PATH
      state = { pid_file: PID_PATH, kill_fn: (pid, sig) -> true }
      status = h_system.handle_reload make_req(""), state
      assert.equals 200, status
      line = one_line "webui_reload_requested"
      assert.truthy line\find("ok=1", 1, true)
      assert.truthy line\find("pid=4242", 1, true)

    it "échec du kill : INFO ok=0 err=kill_failed", ->
      require("lib.pidfile").write 4242, PID_PATH
      state = { pid_file: PID_PATH, kill_fn: (pid, sig) -> false }
      status = h_system.handle_reload make_req(""), state
      assert.equals 500, status
      line = one_line "webui_reload_requested"
      assert.truthy line\find("ok=0", 1, true)
      assert.truthy line\find("err=kill_failed", 1, true)

    it "pidfile absent : INFO ok=0 err=pidfile_unreadable", ->
      state = { pid_file: PID_PATH, kill_fn: (pid, sig) -> true }
      status = h_system.handle_reload make_req(""), state
      assert.equals 500, status
      line = one_line "webui_reload_requested"
      assert.truthy line\find("ok=0", 1, true)
      assert.truthy line\find("err=pidfile_unreadable", 1, true)

  -- ── Routeur : non-admin, propagation user/peer ──────────────────────────

  describe "router", ->

    make_cookie = (user) ->
      tok = token.generate "user", user, ADMIN_MAC, os.time! + 3600, TEST_KEY
      "custos_session=" .. tok

    make_rreq = (method, path, user, body) ->
      {
        method:  method
        path:    path
        headers: { cookie: make_cookie user or "admin" }
        body:    body or ""
        peer_ip: "192.0.2.50"
      }

    make_rstate = ->
      {
        token_key:                  TEST_KEY
        admin_users:                { "admin" }
        admin_allow_all_when_empty: false
        config_path:                CFG_PATH
        sessions_file:              SESS_PATH
      }

    before_each ->
      write_cfg { runtime: { log_level: "INFO" }, filter: { rules: {} } }
      write_sessions { [ADMIN_MAC]: { user: "admin", expires: os.time! + 3600 } }, SESS_PATH

    it "POST admin : user authentifié et peer cliente dans la ligne", ->
      status = router.dispatch make_rreq("POST", "/admin/config/runtime", "admin", "log_level=INFO&benchmark_present=1"), make_rstate!
      assert.equals 302, status
      line = one_line "webui_config_saved"
      assert.truthy line\find("user=admin", 1, true)
      assert.truthy line\find("peer=192.0.2.50", 1, true)

    it "POST non admin : WARN refused forbidden, aucune INFO", ->
      status = router.dispatch make_rreq("POST", "/admin/config/runtime", "stranger", "log_level=INFO"), make_rstate!
      assert.equals 403, status
      no_info "webui_config_saved"
      line = one_line "webui_change_refused", "WARN"
      assert.truthy line\find("reason=forbidden", 1, true)
      assert.truthy line\find("user=stranger", 1, true)
      assert.truthy line\find("peer=192.0.2.50", 1, true)

    it "POST sans session : WARN refused unauth", ->
      req = { method: "POST", path: "/admin/config/runtime", headers: {}, body: "log_level=INFO", peer_ip: "192.0.2.51" }
      status = router.dispatch req, make_rstate!
      assert.equals 302, status
      line = one_line "webui_change_refused", "WARN"
      assert.truthy line\find("reason=unauth", 1, true)
      assert.truthy line\find("peer=192.0.2.51", 1, true)

    it "GET non admin : pas de WARN (lecture, pas une modification)", ->
      status = router.dispatch make_rreq("GET", "/admin/", "stranger"), make_rstate!
      assert.equals 403, status
      assert.equals 0, #lines
