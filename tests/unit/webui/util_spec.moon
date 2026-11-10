-- tests/unit/webui/util_spec.moon
-- Tests de webui/util : échappement HTML (esc) et décodage urlencodé (parse_form).

{ :esc, :parse_form } = require "webui.util"

describe "webui/util", ->

  describe "esc", ->

    it "échappe les cinq caractères HTML", ->
      assert.equals "&amp;&lt;&gt;&quot;&#39;", esc "&<>\"'"

    it "échappe & en premier (pas de double échappement)", ->
      assert.equals "&amp;", esc "&"
      assert.equals "&amp;lt;", esc "&lt;"

    it "accepte nil et renvoie une chaîne vide", ->
      assert.equals "", esc nil

    it "accepte un nombre via tostring", ->
      assert.equals "42", esc 42

    it "laisse intact un texte sans caractère spécial", ->
      assert.equals "Autoriser Wikipédia", esc "Autoriser Wikipédia"

  describe "parse_form", ->

    it "décode deux champs et le + comme espace", ->
      form = parse_form "a=1&b=x+y"
      assert.equals "1", form.a
      assert.equals "x y", form.b

    it "décode les séquences %xx", ->
      form = parse_form "a=%3Cb%3E"
      assert.equals "<b>", form.a

    it "gère une clé sans valeur", ->
      form = parse_form "a=&b=2"
      assert.equals "", form.a
      assert.equals "2", form.b

    it "retourne une table vide pour un corps nil ou vide", ->
      assert.same {}, parse_form nil
      assert.same {}, parse_form ""
