-- tests/unit/webui/dashboard_handler_spec.moon
-- Tests de webui/handlers/dashboard : navigation admin, dont la déconnexion.

{ :handle_dashboard, :nav_html } = require "webui.handlers.dashboard"

make_req = ->
  { method: "GET", path: "/admin/", headers: {}, body: "" }

describe "webui/handlers/dashboard", ->

  describe "handle_dashboard", ->

    it "retourne 200 avec du HTML", ->
      status, hdrs, body = handle_dashboard make_req!, {}
      assert.equals 200, status
      assert.equals "text/html; charset=UTF-8", hdrs["Content-Type"]
      assert.truthy body\find("<html", 1, true)

    it "ne pointe plus vers la route inexistante /admin/logout", ->
      _, _, body = handle_dashboard make_req!, {}
      assert.is_nil body\find("/admin/logout", 1, true)

    it "la déconnexion pointe vers /logout (GET du portail)", ->
      _, _, body = handle_dashboard make_req!, {}
      assert.truthy body\find('href="/logout"', 1, true)
      assert.truthy body\find("Déconnexion", 1, true)

  describe "nav_html", ->

    it "contient le lien de déconnexion du portail", ->
      html = nav_html!
      assert.is_nil html\find("/admin/logout", 1, true)
      assert.truthy html\find('href="/logout"', 1, true)
