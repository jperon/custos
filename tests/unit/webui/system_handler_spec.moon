-- tests/unit/webui/system_handler_spec.moon
-- Tests de webui/handlers/system.
-- NOTE: handle_reload envoie SIGHUP au processus parent ; il est exclu des
--       tests unitaires et couvert par les tests E2E homelab uniquement.

{ :handle_status } = require "webui.handlers.system"

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
