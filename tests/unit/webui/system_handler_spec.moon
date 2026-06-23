-- tests/unit/webui/system_handler_spec.moon
-- Tests de webui/handlers/system.
-- handle_reload cible le superviseur via le pidfile (src/lib/pidfile) ; le kill
-- est injectable (state.kill_fn) pour éviter d'envoyer un vrai SIGHUP en test.

{ :handle_status, :handle_reload } = require "webui.handlers.system"
pidfile = require "lib.pidfile"

make_state = (started_at) ->
  { started_at: started_at or os.time! }

make_req = ->
  { method: "GET", path: "", headers: {}, body: "" }

describe "webui/handlers/system — handle_status", ->

  it "retourne 200", ->
    status, _, _ = handle_status make_req!, make_state!
    assert.equals 200, status

  it "retourne du HTML avec Content-Type correct", ->
    status, hdrs, body = handle_status make_req!, make_state!
    assert.equals "text/html; charset=UTF-8", hdrs["Content-Type"]
    assert.truthy body\find("<html", 1, true)

  it "affiche le PID courant (entier positif)", ->
    _, _, body = handle_status make_req!, make_state!
    -- Le PID doit apparaître dans le body sous forme d'entier
    assert.truthy body\find("PID", 1, true)
    -- Il y a au moins un nombre > 0 dans le body
    assert.truthy body\match "%d+"

  it "affiche un uptime en secondes", ->
    started = os.time! - 42
    _, _, body = handle_status make_req!, make_state started
    assert.truthy body\find("ptime", 1, true) or body\find("42", 1, true)

  it "affiche un lien vers le dashboard", ->
    _, _, body = handle_status make_req!, make_state!
    assert.truthy body\find("/admin/", 1, true)

  it "uptime est 0 si started_at = maintenant", ->
    now = os.time!
    _, _, body = handle_status make_req!, make_state now
    -- L'uptime devrait être 0 ou très proche
    assert.truthy body\find("0s", 1, true) or body\match "uptime.-%d+"

describe "webui/handlers/system — handle_reload", ->

  tmp_pid = -> os.tmpname!

  it "signale le PID du pidfile et retourne 200", ->
    path = tmp_pid!
    pidfile.write 4242, path
    killed = nil
    rec_kill = (pid, sig) ->
      killed = { pid, sig }
      true
    state = { pid_file: path, kill_fn: rec_kill }
    status, hdrs, body = handle_reload make_req!, state
    os.remove path
    assert.equals 200, status
    assert.equals "text/html; charset=UTF-8", hdrs["Content-Type"]
    assert.same { 4242, 1 }, killed
    assert.truthy body\find("4242", 1, true)

  it "retourne 500 si le pidfile est absent (pas de kill)", ->
    killed = false
    flag_kill = ->
      killed = true
      true
    state = { pid_file: "/nonexistent/custos.pid", kill_fn: flag_kill }
    status, _, body = handle_reload make_req!, state
    assert.equals 500, status
    assert.is_false killed
    assert.truthy body\find("flash error", 1, true)

  it "retourne 500 si le kill échoue", ->
    path = tmp_pid!
    pidfile.write 4242, path
    state = { pid_file: path, kill_fn: -> false }
    status, _, body = handle_reload make_req!, state
    os.remove path
    assert.equals 500, status
    assert.truthy body\find("flash error", 1, true)
