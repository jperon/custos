-- tests/unit/auth/html_spec.moon
-- Tests des helpers de génération HTML (auth/html).

h = require "auth.html"

describe "auth/html", ->

  it "balise simple", ->
    assert.equals "<div>hello</div>", h.div("hello")

  it "balise avec attributs", ->
    assert.equals '<div id="test">hello</div>', h.div({ id: "test" }, "hello")

  it "balise auto-fermante", ->
    assert.equals "<br/>", h.br!

  it "balises imbriquées", ->
    result = h.div id: "outer",
      h.p "paragraph"
    assert.truthy result\find('<div id="outer">', 1, true)
    assert.truthy result\find("<p>paragraph</p>", 1, true)
    assert.truthy result\find("</div>", 1, true)

  it "escape wraps dans une balise escape", ->
    result = h.escape "<script>alert('xss')</script>"
    assert.truthy result\find("<escape>", 1, true)
    assert.truthy result\find("</escape>", 1, true)
    -- Le contenu est passé tel quel (wrapping uniquement)
    assert.truthy result\find("<script>", 1, true)
