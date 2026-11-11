-- tests/unit/lib/ipc_hex_spec.moon
-- Helpers de format IPC partagés (émetteur ipc / récepteurs worker_nft, nft_queue).

{ :to_hex, :from_hex, :split_fields, :is_valid_timeout } = require "lib.ipc_hex"

describe "lib.ipc_hex", ->

  describe "to_hex", ->
    it "encode des octets en hexadécimal minuscule", ->
      assert.equals "00ff10", to_hex "\0\255\16"

    it "renvoie une chaîne vide pour une entrée vide ou nil", ->
      assert.equals "", to_hex ""
      assert.equals "", to_hex nil

  describe "from_hex", ->
    it "décode l'hexadécimal, majuscules acceptées", ->
      value, err = from_hex "00FF10"
      assert.is_nil err
      assert.equals "\0\255\16", value

    it "aller-retour to_hex/from_hex", ->
      raw = "\1\2\3\4\5\6"
      value = from_hex to_hex raw
      assert.equals raw, value

    it "renvoie une chaîne vide sans erreur pour une entrée vide", ->
      value, err = from_hex ""
      assert.equals "", value
      assert.is_nil err

    it "rejette une longueur impaire", ->
      value, err = from_hex "abc"
      assert.is_nil value
      assert.equals "hex_odd_length", err

    it "rejette des caractères non hexadécimaux", ->
      value, err = from_hex "zz"
      assert.is_nil value
      assert.equals "hex_invalid_chars", err

  describe "split_fields", ->
    it "découpe sur '|' en préservant les champs vides", ->
      assert.same { "v1", "", "42", "" }, split_fields "v1||42|"

    it "renvoie un seul champ sans séparateur", ->
      assert.same { "seul" }, split_fields "seul"

  describe "is_valid_timeout", ->
    it "accepte un nombre nu et les suffixes nftables", ->
      for t in *{ "60", "30s", "2m", "1h", "5d", "1w" }
        assert.is_true is_valid_timeout(t), t

    it "rejette les valeurs invalides", ->
      for t in *{ "", "2x", "-1", "1.5m", "9999999999999999s", nil, 60 }
        assert.is_false is_valid_timeout(t), tostring t
