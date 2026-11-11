-- tests/unit/lib/json_spec.moon
-- Tests de l'encodeur/décodeur JSON minimal (src/lib/json.moon).

{ :encode, :decode } = require "lib.json"

describe "lib/json", ->

  describe "encode", ->

    it "encode les scalaires", ->
      assert.equals "null", encode nil
      assert.equals "true", encode true
      assert.equals "false", encode false
      assert.equals "42", encode 42
      assert.equals "-3", encode -3
      assert.equals '"abc"', encode "abc"

    it "échappe guillemets, antislash et caractères de contrôle", ->
      assert.equals '"a\\"b\\\\c\\nd\\te"', encode 'a"b\\c\nd\te'

    it "encode une table vide comme tableau vide", ->
      assert.equals "[]", encode {}

    it "encode un tableau et un objet", ->
      assert.equals '["a",1,true]', encode { "a", 1, true }
      assert.equals '{"a":1,"b":"x"}', encode { a: 1, b: "x" }

    it "trie les clés d'objet pour une sortie stable", ->
      assert.equals encode({ a: 1, b: 2 }), encode({ b: 2, a: 1 })

    it "encode en objet une table mixte ou à clés non contiguës", ->
      assert.equals '{"1":"a","x":1}', encode { "a", x: 1 }
      assert.equals '{"1":"a","3":"c"}', encode { [1]: "a", [3]: "c" }

    it "ne boucle pas sur une table cyclique", ->
      t = {}
      t.self = t
      assert.equals '{"self":null}', encode t

  describe "decode", ->

    it "décode les scalaires", ->
      assert.is_nil decode "null"
      assert.is_true decode "true"
      assert.is_false decode "false"
      assert.equals 42, decode "42"
      assert.equals -3.5, decode "-3.5"
      assert.equals 1000, decode "1e3"
      assert.equals "abc", decode '"abc"'

    it "décode les échappements", ->
      assert.equals 'a"b\\c\nd\te', decode '"a\\"b\\\\c\\nd\\te"'
      assert.equals "é", decode '"\\u00e9"'
      assert.equals "😀", decode '"\\ud83d\\ude00"'

    it "décode tableau et objet imbriqués", ->
      v = decode '{"timestamp":12,"rules":[{"rule_id":"r1","verdicts":{"allow":2}}]}'
      assert.equals 12, v.timestamp
      assert.equals "r1", v.rules[1].rule_id
      assert.equals 2, v.rules[1].verdicts.allow

    it "accepte les espaces", ->
      assert.same { 1, 2 }, decode " [ 1 , 2 ] "

    it "rejette une entrée corrompue", ->
      for bad in *{ "", "{", "[1,", '{"a"}', "tru", '"abc', "{} x", "01x" }
        ok = pcall -> decode bad
        assert.is_false ok, "devrait rejeter #{bad}"

  describe "round-trip", ->

    it "encode puis décode une structure de snapshot", ->
      snap = {
        timestamp: 1700000000
        rules: {
          { rule_id: "r1", verdicts: { allow: 3, refuse: 1, dnsonly: 0 } }
          { rule_id: "r<2>", verdicts: { allow: 0, refuse: 2, dnsonly: 1 } }
        }
      }
      assert.same snap, decode encode snap
