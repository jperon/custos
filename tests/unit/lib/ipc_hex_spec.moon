-- tests/unit/lib/ipc_hex_spec.moon
-- Helpers de format IPC partagés (émetteur ipc / récepteurs worker_nft, nft_queue).

{ :encode_ip16, :to_hex, :from_hex, :split_fields, :is_valid_timeout,
  :is_ipv4_str, :is_ipv6_str, :is_valid_mac } = require "lib.ipc_hex"

describe "lib.ipc_hex", ->

  describe "encode_ip16", ->
    it "pade une IPv4 sur 16 octets avec 12 zéros", ->
      assert.equals "\192\168\1\42" .. string.rep("\0", 12), encode_ip16 "\192\168\1\42"

    it "copie une IPv6 sur ses 16 octets", ->
      ip6 = string.rep("\0", 15) .. "\1"
      assert.equals ip6, encode_ip16 ip6

    it "renvoie nil pour une longueur invalide", ->
      assert.is_nil encode_ip16 "\1\2\3"
      assert.is_nil encode_ip16 nil

  describe "to_hex", ->
    it "encode des octets en hexadécimal minuscule", ->
      assert.equals "00ff10", to_hex "\0\255\16"

    it "renvoie une chaîne vide pour une entrée vide ou nil", ->
      assert.equals "", to_hex ""
      assert.equals "", to_hex nil

    -- Garde-fou d'équivalence : l'encodage par table (perf §18) doit rendre
    -- exactement la même sortie que l'encodage de référence, sur TOUS les
    -- octets, y compris ceux qui ont une signification dans les motifs Lua.
    it "est identique à l'encodage de référence sur les 256 octets", ->
      ref = (s) -> (s\gsub ".", (c) -> string.format "%02x", c\byte!)
      all = table.concat [ string.char(i) for i = 0, 255 ]
      assert.equals ref(all), to_hex(all)
      for i = 0, 255
        c = string.char i
        assert.equals ref(c), to_hex(c), "octet #{i}"

    it "préserve le aller-retour avec from_hex sur une chaîne longue", ->
      raw = table.concat [ string.char((i * 7) % 256) for i = 1, 300 ]
      assert.equals raw, (from_hex to_hex raw)

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
      value, err = from_hex nil
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
      value, err = from_hex "0g"
      assert.is_nil value
      assert.equals "hex_invalid_chars", err

    it "préfère hex_odd_length à hex_invalid_chars (ordre de vérification)", ->
      value, err = from_hex "zzz"
      assert.is_nil value
      assert.equals "hex_odd_length", err

    it "décodé puis encodé est identique sur tous les octets", ->
      all = table.concat [ string.char(i) for i = 0, 255 ]
      assert.equals all, (from_hex (to_hex all))

  describe "split_fields", ->
    it "découpe sur '|' en préservant les champs vides", ->
      assert.same { "v1", "", "42", "" }, split_fields "v1||42|"

    it "renvoie un seul champ sans séparateur", ->
      assert.same { "seul" }, split_fields "seul"

  describe "validateurs IPC", ->
    it "is_ipv4_str accepte une IPv4 pointée et rejette le reste", ->
      assert.is_truthy is_ipv4_str "192.168.1.42"
      assert.is_falsy is_ipv4_str "192.168.1"
      assert.is_falsy is_ipv4_str "2001:db8::1"
      assert.is_falsy is_ipv4_str nil

    it "is_ipv6_str détecte la présence de ':'", ->
      assert.is_truthy is_ipv6_str "2001:db8::1"
      assert.is_falsy is_ipv6_str "192.168.1.42"
      assert.is_falsy is_ipv6_str nil

    it "is_valid_mac accepte aa:bb:cc:dd:ee:ff et rejette le reste", ->
      assert.is_truthy is_valid_mac "aa:bb:cc:dd:ee:ff"
      assert.is_truthy is_valid_mac "AA:BB:CC:DD:EE:FF"
      assert.is_falsy is_valid_mac "aa:bb:cc:dd:ee"
      assert.is_falsy is_valid_mac "aa-bb-cc-dd-ee-ff"
      assert.is_falsy is_valid_mac nil

  describe "is_valid_timeout", ->
    it "accepte un nombre nu et les suffixes nftables", ->
      for t in *{ "60", "30s", "2m", "1h", "5d", "1w" }
        assert.is_true is_valid_timeout(t), t

    it "rejette les valeurs invalides", ->
      for t in *{ "", "2x", "-1", "1.5m", "9999999999999999s", nil, 60 }
        assert.is_false is_valid_timeout(t), tostring t
