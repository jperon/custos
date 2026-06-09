-- tests/unit/auth/success_page_spec.moon
-- Tests de auth.pages.success_page : présence/absence du lien admin.

{ :success_page } = require "auth.pages"

cfg_base = { heartbeat_interval: 30, idle_timeout: 90 }

describe "auth.pages.success_page", ->

  it "retourne du HTML valide (DOCTYPE + html)", ->
    html = success_page cfg_base, os.time!, false
    assert.truthy html\find("<!DOCTYPE html>", 1, true)
    assert.truthy html\find("<html", 1, true)

  it "contient toujours le lien /logout", ->
    html = success_page cfg_base, os.time!, false
    assert.truthy html\find("/logout", 1, true)

  it "contient le texte de connexion réussie", ->
    html = success_page cfg_base, os.time!, false
    assert.truthy html\find("Connexion", 1, true)

  it "is_admin=false → pas de lien /admin", ->
    html = success_page cfg_base, os.time!, false
    assert.falsy html\find("/admin", 1, true)

  it "is_admin=true → lien /admin présent", ->
    html = success_page cfg_base, os.time!, true
    assert.truthy html\find("/admin", 1, true)

  it "is_admin=true → texte 'Administration' présent", ->
    html = success_page cfg_base, os.time!, true
    assert.truthy html\find("Administration", 1, true)

  it "is_admin=nil → pas de lien /admin", ->
    html = success_page cfg_base, os.time!, nil
    assert.falsy html\find("/admin", 1, true)

  it "heartbeat_interval est injecté dans le JS", ->
    html = success_page { heartbeat_interval: 42, idle_timeout: 90 }, 0, false
    assert.truthy html\find("42", 1, true)

  it "session_start est injecté dans le JS", ->
    html = success_page cfg_base, 1234567890, false
    assert.truthy html\find("1234567890", 1, true)

  it "délègue le ping à un web worker inline", ->
    html = success_page cfg_base, os.time!, false
    assert.truthy html\find("Worker", 1, true)
    assert.truthy html\find("workerJs", 1, true)
    assert.truthy html\find("postMessage", 1, true)
    assert.truthy html\find("tick", 1, true)
    assert.truthy html\find("fetch('/ping'", 1, true)
