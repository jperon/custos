-- tests/unit/doh/hpack_spec.moon
-- Vecteurs de l'annexe C de la RFC 7541 + cas d'erreur et encodeur minimal.

hpack = require "doh.hpack"

--- Convertit un dump hexadécimal (espaces ignorés) en chaîne d'octets.
from_hex = (s) ->
  s = s\gsub "%s+", ""
  assert #s % 2 == 0, "hexadécimal de longueur impaire"
  out = {}
  for i = 1, #s, 2
    out[#out + 1] = string.char tonumber s\sub(i, i + 1), 16
  table.concat out

--- Extrait les paires {name, value} d'une liste de en-têtes décodés.
pairs_of = (headers) ->
  out = {}
  for h in *headers
    out[#out + 1] = { h[1], h[2] }
  out

describe "doh.hpack — C.2 représentations isolées", ->

  it "C.2.1 littéral avec indexation (nouveau nom)", ->
    d = hpack.new_decoder!
    headers, err = hpack.decode d, from_hex "400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572"
    assert.is_nil err
    assert.same { { "custom-key", "custom-header" } }, pairs_of headers
    -- 10 + 13 + 32 = 55 octets dans la table dynamique.
    assert.equals 55, d.size
    assert.equals 1, #d.entries

  it "C.2.2 littéral sans indexation (nom indexé)", ->
    d = hpack.new_decoder!
    headers, err = hpack.decode d, from_hex "040c 2f73 616d 706c 652f 7061 7468"
    assert.is_nil err
    assert.same { { ":path", "/sample/path" } }, pairs_of headers
    assert.equals 0, d.size
    assert.equals 0, #d.entries

  it "C.2.3 littéral jamais indexé", ->
    d = hpack.new_decoder!
    headers, err = hpack.decode d, from_hex "1008 7061 7373 776f 7264 0673 6563 7265 74"
    assert.is_nil err
    assert.same { { "password", "secret" } }, pairs_of headers
    assert.equals 0, d.size
    assert.equals 0, #d.entries

  it "C.2.4 champ indexé de la table statique", ->
    d = hpack.new_decoder!
    headers, err = hpack.decode d, from_hex "82"
    assert.is_nil err
    assert.same { { ":method", "GET" } }, pairs_of headers
    assert.equals 0, d.size

  it "entier à préfixe : C.1.2 (1337 sur 5 bits)", ->
    -- 0x1f puis 0x9a 0x0a : 31 + 26 + 10*128 = 1337.
    value, pos, err = hpack.decode_integer from_hex("1f 9a 0a"), 1, 5
    assert.is_nil err
    assert.equals 1337, value
    assert.equals 4, pos

describe "doh.hpack — C.3 requêtes sans Huffman", ->

  it "décode les trois requêtes successives et fait évoluer la table dynamique", ->
    d = hpack.new_decoder!

    h1, e1 = hpack.decode d, from_hex "8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d"
    assert.is_nil e1
    assert.same {
      { ":method", "GET" }
      { ":scheme", "http" }
      { ":path", "/" }
      { ":authority", "www.example.com" }
    }, pairs_of h1
    assert.equals 57, d.size

    h2, e2 = hpack.decode d, from_hex "8286 84be 5808 6e6f 2d63 6163 6865"
    assert.is_nil e2
    assert.same {
      { ":method", "GET" }
      { ":scheme", "http" }
      { ":path", "/" }
      { ":authority", "www.example.com" }
      { "cache-control", "no-cache" }
    }, pairs_of h2
    assert.equals 110, d.size

    h3, e3 = hpack.decode d, from_hex "8287 85bf 400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65"
    assert.is_nil e3
    assert.same {
      { ":method", "GET" }
      { ":scheme", "https" }
      { ":path", "/index.html" }
      { ":authority", "www.example.com" }
      { "custom-key", "custom-value" }
    }, pairs_of h3
    assert.equals 164, d.size

describe "doh.hpack — C.4 requêtes avec Huffman", ->

  it "décode les trois requêtes Huffman et valide la table de l'annexe B", ->
    d = hpack.new_decoder!

    h1, e1 = hpack.decode d, from_hex "8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff"
    assert.is_nil e1
    assert.same {
      { ":method", "GET" }
      { ":scheme", "http" }
      { ":path", "/" }
      { ":authority", "www.example.com" }
    }, pairs_of h1
    assert.equals 57, d.size

    h2, e2 = hpack.decode d, from_hex "8286 84be 5886 a8eb 1064 9cbf"
    assert.is_nil e2
    assert.same {
      { ":method", "GET" }
      { ":scheme", "http" }
      { ":path", "/" }
      { ":authority", "www.example.com" }
      { "cache-control", "no-cache" }
    }, pairs_of h2

    h3, e3 = hpack.decode d, from_hex "8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf"
    assert.is_nil e3
    assert.same {
      { ":method", "GET" }
      { ":scheme", "https" }
      { ":path", "/index.html" }
      { ":authority", "www.example.com" }
      { "custom-key", "custom-value" }
    }, pairs_of h3
    assert.equals 164, d.size

describe "doh.hpack — C.5 réponses sans Huffman (table 256)", ->

  it "décode les trois réponses et gère les évictions", ->
    d = hpack.new_decoder { max_table_size: 256 }

    h1, e1 = hpack.decode d, from_hex [[
      4803 3330 3258 0770 7269 7661 7465 611d 4d6f 6e2c 2032 3120
      4f63 7420 3230 3133 2032 303a 3133 3a32 3120 474d 546e 1768
      7474 7073 3a2f 2f77 7777 2e65 7861 6d70 6c65 2e63 6f6d
    ]]
    assert.is_nil e1
    assert.same {
      { ":status", "302" }
      { "cache-control", "private" }
      { "date", "Mon, 21 Oct 2013 20:13:21 GMT" }
      { "location", "https://www.example.com" }
    }, pairs_of h1
    assert.equals 222, d.size

    h2, e2 = hpack.decode d, from_hex "4803 3330 37c1 c0bf"
    assert.is_nil e2
    assert.same {
      { ":status", "307" }
      { "cache-control", "private" }
      { "date", "Mon, 21 Oct 2013 20:13:21 GMT" }
      { "location", "https://www.example.com" }
    }, pairs_of h2
    assert.equals 222, d.size

    h3, e3 = hpack.decode d, from_hex [[
      88c1 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 2032 303a
      3133 3a32 3220 474d 54c0 5a04 677a 6970 7738 666f 6f3d
      4153 444a 4b48 514b 425a 584f 5157 454f 5049 5541 5851 5745
      4f49 553b 206d 6178 2d61 6765 3d33 3630 303b 2076 6572 7369
      6f6e 3d31
    ]]
    assert.is_nil e3
    assert.same {
      { ":status", "200" }
      { "cache-control", "private" }
      { "date", "Mon, 21 Oct 2013 20:13:22 GMT" }
      { "location", "https://www.example.com" }
      { "content-encoding", "gzip" }
      { "set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1" }
    }, pairs_of h3
    assert.equals 215, d.size

describe "doh.hpack — C.6 réponses avec Huffman (table 256)", ->

  it "décode les trois réponses Huffman et gère les évictions", ->
    d = hpack.new_decoder { max_table_size: 256 }

    h1, e1 = hpack.decode d, from_hex [[
      4882 6402 5885 aec3 771a 4b61 96d0 7abe 9410 54d4 44a8 2005
      9504 0b81 66e0 82a6 2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8
      e9ae 82ae 43d3
    ]]
    assert.is_nil e1
    assert.same {
      { ":status", "302" }
      { "cache-control", "private" }
      { "date", "Mon, 21 Oct 2013 20:13:21 GMT" }
      { "location", "https://www.example.com" }
    }, pairs_of h1
    assert.equals 222, d.size

    h2, e2 = hpack.decode d, from_hex "4883 640e ffc1 c0bf"
    assert.is_nil e2
    assert.same {
      { ":status", "307" }
      { "cache-control", "private" }
      { "date", "Mon, 21 Oct 2013 20:13:21 GMT" }
      { "location", "https://www.example.com" }
    }, pairs_of h2
    assert.equals 222, d.size

    h3, e3 = hpack.decode d, from_hex [[
      88c1 6196 d07a be94 1054 d444 a820 0595 040b 8166 e084 a62d
      1bff c05a 839b d9ab 77ad 94e7 821d d7f2 e6c7 b335 dfdf cd5b
      3960 d5af 2708 7f36 72c1 ab27 0fb5 291f 9587 3160 65c0 03ed
      4ee5 b106 3d50 07
    ]]
    assert.is_nil e3
    assert.same {
      { ":status", "200" }
      { "cache-control", "private" }
      { "date", "Mon, 21 Oct 2013 20:13:22 GMT" }
      { "location", "https://www.example.com" }
      { "content-encoding", "gzip" }
      { "set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1" }
    }, pairs_of h3
    assert.equals 215, d.size

describe "doh.hpack — cas d'erreur", ->

  it "index 0 refusé", ->
    d = hpack.new_decoder!
    headers, err = hpack.decode d, "\x80"
    assert.is_nil headers
    assert.equals "index_zero", err

  it "index hors table refusé", ->
    d = hpack.new_decoder!
    headers, err = hpack.decode d, "\xff\x00"
    assert.is_nil headers
    assert.equals "index_out_of_range", err

  it "entier tronqué refusé", ->
    d = hpack.new_decoder!
    headers, err = hpack.decode d, "\xff"
    assert.is_nil headers
    assert.equals "truncated_integer", err

  it "entier trop long refusé (six octets de continuation)", ->
    d = hpack.new_decoder!
    headers, err = hpack.decode d, "\xff\x80\x80\x80\x80\x80\x00"
    assert.is_nil headers
    assert.equals "integer_too_long", err

  it "chaîne tronquée refusée", ->
    d = hpack.new_decoder!
    headers, err = hpack.decode d, "\x40\x05ab"
    assert.is_nil headers
    assert.equals "truncated_string", err

  it "chaîne plus longue que le plafond refusée", ->
    d = hpack.new_decoder { max_header_size: 8 }
    headers, err = hpack.decode d, "\x04\x0a" .. string.rep("a", 10)
    assert.is_nil headers
    assert.equals "string_too_long", err

  it "sortie Huffman plus longue que le plafond refusée", ->
    encoded = from_hex "f1e3 c2e5 f23a 6ba0 ab90 f4ff"
    decoded, err = hpack.huffman_decode encoded, 5
    assert.is_nil decoded
    assert.equals "string_too_long", err

  it "symbole EOS Huffman refusé", ->
    d = hpack.new_decoder!
    headers, err = hpack.decode d, "\x40\x84\xff\xff\xff\xfc"
    assert.is_nil headers
    assert.equals "huffman_eos", err

  it "padding Huffman non composé de 1 refusé", ->
    d = hpack.new_decoder!
    headers, err = hpack.decode d, "\x40\x81\x00"
    assert.is_nil headers
    assert.equals "huffman_invalid_padding", err

  it "padding Huffman de plus de 7 bits refusé", ->
    d = hpack.new_decoder!
    headers, err = hpack.decode d, "\x40\x82\xff\xff"
    assert.is_nil headers
    assert.equals "huffman_invalid_padding", err

  it "taille totale d'en-têtes décodés plafonnée", ->
    d = hpack.new_decoder { max_header_size: 64 }
    -- :path (5) + valeur de 64 octets + 32 > 64.
    headers, err = hpack.decode d, "\x04\x40" .. string.rep("a", 64)
    assert.is_nil headers
    assert.equals "header_list_too_large", err

  it "dynamic table size update au-delà de la limite refusé", ->
    d = hpack.new_decoder { max_table_size: 256 }
    headers, err = hpack.decode d, "\x3f\xe2\x01"
    assert.is_nil headers
    assert.equals "dynamic_table_size_update_too_large", err

  it "dynamic table size update après un champ refusé", ->
    d = hpack.new_decoder!
    headers, err = hpack.decode d, "\x82\x20"
    assert.is_nil headers
    assert.equals "dynamic_table_size_update_invalid", err

describe "doh.hpack — dynamic table size update", ->

  it "réduit la table et évince les entrées les plus anciennes", ->
    d = hpack.new_decoder!
    _, e = hpack.decode d, from_hex "400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572"
    assert.is_nil e
    assert.equals 55, d.size
    -- size update à 0 : la table est vidée.
    _, e2 = hpack.decode d, "\x20"
    assert.is_nil e2
    assert.equals 0, d.size
    assert.equals 0, #d.entries

describe "doh.hpack — encodeur minimal", ->

  it "émet les champs indexés de la table statique", ->
    assert.equals "\x82", hpack.encode { { ":method", "GET" } }
    assert.equals "\x88", hpack.encode { { ":status", "200" } }
    assert.equals "\x8d", hpack.encode { { ":status", "404" } }

  it "émet un littéral sans indexation avec nom indexé", ->
    block = hpack.encode { { ":status", "405" } }
    -- index 8 (:status) sur 4 bits, puis longueur 3 et "405".
    assert.equals "\x08\x03" .. "405", block

  it "émet un littéral sans indexation avec nom littéral", ->
    block = hpack.encode { { "x-test", "abc" } }
    assert.equals "\x00\x06x-test\x03abc", block

  it "aller-retour avec un décodeur neuf", ->
    original = {
      { ":method", "POST" }
      { ":scheme", "https" }
      { ":path", "/dns-query" }
      { ":authority", "192.0.2.1:8443" }
      { "content-type", "application/dns-message" }
      { "x-long", string.rep "z", 200 }
    }
    block = hpack.encode original
    d = hpack.new_decoder!
    headers, err = hpack.decode d, block
    assert.is_nil err
    assert.same original, pairs_of headers

  it "encode/décode les entiers de longueur étendue", ->
    for n in *{ 0, 1, 15, 16, 127, 128, 1337, 4096, 65535 }
      encoded = hpack.encode_integer n, 7, 0
      value, pos, err = hpack.decode_integer encoded, 1, 7
      assert.is_nil err
      assert.equals n, value
      assert.equals #encoded + 1, pos

describe "doh.hpack — header_value", ->

  it "retourne la valeur du pseudo-en-tête demandé", ->
    headers = { { ":method", "GET" }, { ":path", "/dns-query" } }
    assert.equals "GET", hpack.header_value headers, ":method"
    assert.equals "/dns-query", hpack.header_value headers, ":path"
    assert.is_nil hpack.header_value headers, ":authority"
