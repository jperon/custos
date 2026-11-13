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

    -- Le cache de conversion (perf §18) ne doit changer ni la sortie ni
    -- l'ARITÉ : `to_hex` rend exactement une valeur, comme avant le cache.
    -- Une deuxième valeur casserait `nft_queue.build_line`, qui place
    -- `to_hex corr` en dernier champ d'un constructeur de table : elle y
    -- ajouterait un 10e champ, `worker_nft.parse_line` exigeant 9 champs
    -- rejetterait TOUTES les insertions nft (régression e2e T03/T74, puis
    -- absence de SYN → plus de log `sni_captured`, T121-T124b).
    it "rend exactement une valeur, y compris sur un hit du cache", ->
      s = "\1\2\3"
      assert.equals 1, select "#", to_hex s
      assert.equals "010203", to_hex s
      -- Second appel : hit du cache, même arité.
      assert.equals 1, select "#", to_hex s

    it "reste exact après le débordement du cache (entrées multiples)", ->
      for i = 1, 20
        s = string.rep(string.char(i), 4)
        expected = string.rep(string.format("%02x", i), 4)
        assert.equals expected, (to_hex s), "entrée #{i}"
      -- Le premier encodé a été purgé puis réencodé : sortie toujours juste.
      assert.equals "01010101", (to_hex string.rep("\1", 4))

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

    it "rend la même sortie sur un appel répété (cache) sans erreur", ->
      value, err = from_hex "616263"
      assert.equals "abc", value
      assert.is_nil err
      value2, err2 = from_hex "616263"
      assert.equals "abc", value2
      assert.is_nil err2

    it "reste exact après le débordement du cache et ne met jamais en cache une erreur", ->
      for i = 1, 20
        hex = string.format "%02x%02x%02x%02x", i, i, i, i
        value = from_hex hex
        assert.equals string.char(i, i, i, i), value, "entrée #{i}"
      -- Une entrée invalide après des succès : erreur toujours détectée.
      assert.is_nil (from_hex "zz")
      assert.equals "abc", (from_hex "616263")

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

    -- Équivalence stricte avec le motif historique `^%d+[smhdw]?$` (validation
    -- réécrite en boucle d'octets pour le hot path, cf. docs/agents/perf.md §26).
    it "équivaut au motif ^%d+[smhdw]?$ sur un corpus", ->
      corpus = {
        "0", "00", "1s", "60", "660s", "2m", "1h", "5d", "1w", "2M", "2S"
        "", "s", "2ss", "2 s", " 2s", "2s ", "1.5m", "-1", "+1", "2x", "2ms"
        "1234567890123456", "12345678901234567", "0d0", "1w1", "12h"
      }
      for t in *corpus
        -- L'ancienne implémentation bornait la longueur à 1..16 avant le motif.
        expected = #t > 0 and #t <= 16 and t\match("^%d+[smhdw]?$") ~= nil
        assert.is_equal expected, is_valid_timeout(t), "timeout #{t}"

  describe "équivalence des validateurs réécrits", ->
    -- Réécriture en boucle d'octets : mêmes acceptations que les motifs
    -- historiques, vérifiées sur un corpus (y compris cas limites).
    it "is_ipv4_str équivaut à ^%d+%.%d+%.%d+%.%d+$", ->
      corpus = {
        "0.0.0.0", "10.35.1.2", "255.255.255.255", "999.1.1.1", "1.1.1.1"
        "1.1.1", "1.1.1.1.1", "1..1.1", ".1.1.1", "1.1.1.", "a.b.c.d"
        "1.1.1.1 ", " 1.1.1.1", "1.1.1.1x", "1-1-1-1", "::1", "", "1234.5.6.7"
      }
      for t in *corpus
        expected = t\match("^%d+%.%d+%.%d+%.%d+$") ~= nil
        assert.is_equal expected, is_ipv4_str(t), "ipv4 #{t}"

    it "is_valid_mac équivaut au motif historique", ->
      pattern = "^[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]$"
      corpus = {
        "aa:bb:cc:dd:ee:ff", "AA:BB:CC:DD:EE:FF", "00:00:00:00:00:00"
        "a8:d3:85:63:6b:27", "aa:bb:cc:dd:ee", "aa-bb-cc-dd-ee-ff"
        "aa:bb:cc:dd:ee:ff:00", "aaa:bb:cc:dd:ee:f", "gg:bb:cc:dd:ee:ff"
        "", "aa:bb:cc:dd:ee:fg"
      }
      for t in *corpus
        expected = t\match(pattern) ~= nil
        assert.is_equal expected, is_valid_mac(t), "mac #{t}"
      assert.is_falsy is_valid_mac nil
