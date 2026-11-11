-- tests/unit/lib/tsv_spec.moon
-- Formatage des champs TSV écrits sur le pipe worker_events.

{ :tsv_field } = require "lib.tsv"

describe "lib.tsv", ->

  describe "tsv_field", ->
    it "conserve une valeur non vide", ->
      assert.equals "example.com", tsv_field "example.com"

    it "convertit les nombres en texte", ->
      assert.equals "42", tsv_field 42

    it "remplace nil par '-'", ->
      assert.equals "-", tsv_field nil

    it "remplace une chaîne vide par '-'", ->
      assert.equals "-", tsv_field ""

    it "conserve '0' et 'false' (non vides une fois formatés)", ->
      assert.equals "0", tsv_field 0
      assert.equals "false", tsv_field false
