-- tests/unit/webui/audit_spec.moon
-- Tests du helper d'audit de l'interface admin (webui/audit) : une ligne INFO
-- par modification, WARN pour un refus, jamais de valeur/secret journalisé.

ffi = require "ffi"

describe "webui/audit", ->
  local log, audit, lines
  local saved_log, saved_config, saved_ffi_defs, saved_audit

  setup ->
    saved_log      = package.loaded["log"]
    saved_config   = package.loaded["config"]
    saved_ffi_defs = package.loaded["ffi_defs"]
    saved_audit    = package.loaded["webui.audit"]

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
    package.loaded["config"]   = { runtime: { log_level: "INFO" } }
    package.loaded["log"]      = nil
    package.loaded["webui.audit"] = nil
    log   = require "log"
    audit = require "webui.audit"

  teardown ->
    package.loaded["log"]         = saved_log
    package.loaded["config"]      = saved_config
    package.loaded["ffi_defs"]    = saved_ffi_defs
    package.loaded["webui.audit"] = saved_audit

  before_each ->
    log._rl_reset!
    log.set_action_prefix ""
    lines = {}

  after_each ->
    log.set_action_prefix ""

  only_lines = (level) ->
    [l for l in *lines when l\find(" #{level} ", 1, true)]

  make_req = (user, peer) ->
    { admin_user: user or "alice", peer_ip: peer or "192.0.2.10" }

  it "change émet exactement une ligne INFO avec user, peer, objet et ok=1", ->
    audit.change make_req!, "webui_config_saved", { section: "runtime" }
    infos = only_lines "INFO"
    assert.equals 1, #infos
    line = infos[1]
    assert.truthy line\find("action=webui_config_saved", 1, true)
    assert.truthy line\find("user=alice", 1, true)
    assert.truthy line\find("peer=192.0.2.10", 1, true)
    assert.truthy line\find("section=runtime", 1, true)
    assert.truthy line\find("ok=1", 1, true)

  it "fail émet une INFO ok=0 avec un code d'erreur court", ->
    audit.fail make_req!, "webui_rule_saved", { rule_id: 3 }, "write_config"
    infos = only_lines "INFO"
    assert.equals 1, #infos
    assert.truthy infos[1]\find("action=webui_rule_saved", 1, true)
    assert.truthy infos[1]\find("rule_id=3", 1, true)
    assert.truthy infos[1]\find("ok=0", 1, true)
    assert.truthy infos[1]\find("err=write_config", 1, true)

  it "refused émet un WARN webui_change_refused, pas d'INFO", ->
    audit.refused make_req!, "forbidden"
    assert.equals 0, #only_lines "INFO"
    warns = only_lines "WARN"
    assert.equals 1, #warns
    assert.truthy warns[1]\find("action=webui_change_refused", 1, true)
    assert.truthy warns[1]\find("reason=forbidden", 1, true)
    assert.truthy warns[1]\find("peer=192.0.2.10", 1, true)

  it "n'émet jamais un champ hors liste blanche (valeur/secret)", ->
    secret = "SUPER_SECRET_AUDIT_42"
    audit.change make_req!, "webui_config_saved", {
      section: "auth"
      password: secret
      value:    secret
      secrets:  secret
    }
    assert.equals 1, #lines
    assert.is_nil lines[1]\find(secret, 1, true)
    assert.truthy lines[1]\find("section=auth", 1, true)

  it "conserve les métadonnées autorisées numériques (pid)", ->
    audit.change make_req!, "webui_reload_requested", { pid: 4242 }
    assert.equals 1, #lines
    assert.truthy lines[1]\find("pid=4242", 1, true)

  it "req absente → user=? et peer=unknown (jamais nil)", ->
    audit.refused nil, "forbidden"
    warns = only_lines "WARN"
    assert.equals 1, #warns
    assert.truthy warns[1]\find("user=?", 1, true)
    assert.truthy warns[1]\find("peer=unknown", 1, true)

  it "assainit un code d'erreur (pas de saut de ligne ni d'espace)", ->
    audit.fail make_req!, "webui_list_saved", { list: "domain" }, "bad value\ncode"
    assert.equals 1, #lines
    assert.truthy lines[1]\find("err=bad_value_code", 1, true)

  it "assainit les valeurs d'objet contrôlées par l'utilisateur", ->
    malicious = "evil\n ok=1 user=admin\t=\""
    audit.change make_req!, "webui_device_saved", {
      name:    malicious
      new:     "x=y"
      list:    "a\tb"
      mac:     "\"q\""
      section: "s\ne"
      dir:     "d d"
    }
    assert.equals 1, #lines
    line = lines[1]\gsub "\n$", ""
    assert.is_nil line\find("\n", 1, true)
    assert.is_nil line\find(" ok=1 user=admin", 1, true)
    assert.is_nil line\find(" user=admin", 1, true)
    assert.truthy line\find("name=evil__ok_1_user_admin", 1, true)
    -- Une seule vraie paire ok=1 : celle émise par le helper.
    _, n_ok = line\gsub "ok=1", ""
    assert.equals 1, n_ok
    assert.truthy line\find("new=x_y", 1, true)
    assert.truthy line\find("list=a_b", 1, true)
    assert.truthy line\find("mac=_q_", 1, true)
    assert.truthy line\find("section=s_e", 1, true)
    assert.truthy line\find("dir=d_d", 1, true)

  it "borne une valeur d'objet à 64 caractères", ->
    long = string.rep "A", 10000
    audit.change make_req!, "webui_config_saved", { name: long }
    assert.equals 1, #lines
    v = lines[1]\match "name=([^%s]+)"
    assert.not_nil v
    assert.equals 64, #v
    assert.truthy #lines[1] < 300

  it "sous préfixe auth_ : audit en auth_webui_*, jamais limité, refus limité", ->
    log.set_action_prefix "auth_"
    package.loaded["webui.audit"] = nil
    audit_auth = require "webui.audit"

    log.log_info -> { action: "ordinary_before" }
    for _ = 1, 5
      audit_auth.change make_req!, "webui_config_saved", { section: "runtime" }
    log.log_info -> { action: "ordinary_after" }

    infos = [l for l in *lines when l\find(" INFO ", 1, true)]
    audit_lines = [l for l in *infos when l\find("action=auth_webui_config_saved", 1, true)]
    assert.equals 5, #audit_lines, "5 modifications identiques doivent émettre 5 lignes"
    ordinary = [l for l in *infos when l\find("action=auth_ordinary_", 1, true)]
    assert.equals 2, #ordinary, "le préfixe auth_ des logs ordinaires doit être préservé"
    unprefixed = [l for l in *infos when l\find("action=webui_config_saved", 1, true)]
    assert.equals 0, #unprefixed

    for _ = 1, 5
      audit_auth.refused make_req!, "forbidden"
    warns = [l for l in *lines when l\find(" WARN ", 1, true) and l\find("action=auth_webui_change_refused", 1, true)]
    assert.equals 1, #warns, "webui_change_refused doit rester limité par (peer, reason)"

  it "toutes les actions webui sont dans RL_NEVER_LIMIT", ->
    actions = {
      "webui_config_saved", "webui_nets_saved", "webui_nets_deleted"
      "webui_macs_saved", "webui_macs_deleted"
      "webui_users_saved", "webui_users_deleted"
      "webui_times_saved", "webui_times_deleted"
      "webui_decision_saved"
      "webui_rule_saved", "webui_rule_deleted", "webui_rule_toggled"
      "webui_rule_moved", "webui_rules_reordered"
      "webui_list_saved", "webui_list_deleted", "webui_list_renamed"
      "webui_device_saved", "webui_reload_requested"
    }
    for action in *actions
      assert.is_true log._rl_never_limited(action), "action non exemptée : #{action}"

  it "webui_change_refused est limitée par (peer, reason) sur 60 s", ->
    cfg = log.RL_CONFIG["webui_change_refused"]
    assert.not_nil cfg
    assert.same { "peer", "reason" }, cfg.keys
    assert.equals 60, cfg.window
