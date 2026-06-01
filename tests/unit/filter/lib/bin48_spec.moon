-- tests/unit/filter/lib/bin48_spec.moon
-- Vérifie la variante 48 bits du stockage des listes :
--   • round-trip pack → rec_at (chaque octet little-endian correct) ;
--   • équivalence de lookup avec un oracle (ensemble Lua des hashes tronqués)
--     sur un grand échantillon de domaines réels : tout présent est trouvé
--     (jamais de faux négatif), aucun absent n'est trouvé sauf collision de
--     troncature (qui ne peut produire qu'un faux positif, jamais un négatif).

ffi      = require "ffi"
bin48    = require "filter.lib.bin48"
{ :xxh64 }   = require "ffi_xxhash"

-- Construit le buffer 48 bits empaqueté + l'oracle (ensemble des hashes
-- tronqués, indexés par leur représentation décimale) à partir de domaines.
build = (domains) ->
  seen, oracle, h48 = {}, {}, {}
  for d in *domains
    continue if seen[d]
    seen[d] = true
    t = bin48.truncate xxh64 d
    h48[#h48 + 1] = t
    oracle[tostring t] = true
  table.sort h48, (a, b) -> a < b
  n = #h48
  packed = bin48.pack h48, n
  arr8 = ffi.cast "const uint8_t*", packed
  -- Conserver une réf sur `packed` pour empêcher son GC tant qu'arr8 vit.
  oracle, arr8, n, packed

describe "filter.lib.bin48", ->

  it "round-trip : rec_at relit ce que pack a écrit (little-endian)", ->
    vals = { 0ULL, 1ULL, 255ULL, 256ULL, 0xFFFFFFFFFFFFULL, 0x0102030405ULL }
    table.sort vals, (a, b) -> a < b
    n = #vals
    packed = bin48.pack vals, n
    arr8 = ffi.cast "const uint8_t*", packed
    for i = 1, n
      assert.is_true bin48.rec_at(arr8, i - 1) == vals[i]

  it "rec_at_bytewise et rec_at_unaligned coïncident (portabilité MIPS)", ->
    vals = [bin48.truncate(xxh64 "x#{i}.example.com") for i = 1, 500]
    table.sort vals, (a, b) -> a < b
    n = #vals
    packed = bin48.pack vals, n   -- retenir la réf : sinon GC → arr8 pendouille
    arr8 = ffi.cast "const uint8_t*", packed
    for i = 0, n - 1
      bw = bin48.rec_at_bytewise arr8, i
      un = bin48.rec_at_unaligned arr8, i
      assert.is_true bw == un, "divergence à l'index #{i}"
      assert.is_true bw == vals[i + 1]

  it "pack_domains : déduplique, trie et empaquette (6 octets/entrée)", ->
    payload, n = bin48.pack_domains { "b.com", "a.com", "b.com", "a.com", "c.com" }
    assert.equal 3, n                 -- 5 entrées, 2 doublons éliminés
    assert.equal 3 * 6, #payload
    -- Vérifier le tri croissant des enregistrements relus.
    arr8 = ffi.cast "const uint8_t*", payload
    for i = 0, n - 2
      assert.is_true bin48.rec_at(arr8, i) < bin48.rec_at(arr8, i + 1)

  it "pack_domains : liste vide → (\"\", 0)", ->
    payload, n = bin48.pack_domains {}
    assert.equal 0, n
    assert.equal "", payload

  it "tronque bien à 48 bits", ->
    assert.is_true bin48.truncate(0xAABBCCDDEEFF1122ULL) == 0xCCDDEEFF1122ULL
    assert.is_true bin48.truncate(0xFFFFFFFFFFFFULL) == 0xFFFFFFFFFFFFULL

  it "équivalence de lookup avec l'oracle sur domaines réels", ->
    -- Échantillon de domaines variés (présents) + requêtes absentes.
    present = {
      "userapi.com", "sun1-13.userapi.com", "evil.example", "ads.tracker.net",
      "google.com", "mail.google.com", "a.b.c.d.example.org", "xn--80ak6aa92e.com",
      "très-long-domaine-avec-beaucoup-de-labels.sub.region.example.co.uk",
    }
    -- Générer du volume pour stresser le bsearch.
    present[#present + 1] = "host#{i}.batch#{i % 7}.example#{i % 3}.net" for i = 1, 5000

    oracle, arr8, n, _keep = build present

    lookup48 = (dom) -> bin48.bsearch arr8, n, bin48.truncate xxh64 dom

    -- Tous les présents : le bsearch 48 bits doit dire « trouvé ».
    for dom in *present
      assert.is_true lookup48(dom), "uint48 devrait trouver #{dom}"

    -- Absents : l'oracle dit « non » (clé tronquée absente) ; le bsearch doit
    -- dire « non » aussi, SAUF collision de troncature (extrêmement rare).
    -- On vérifie qu'il n'y a jamais de faux négatif (déjà couvert ci-dessus)
    -- et qu'aucun faux positif n'apparaît sur cet échantillon modeste.
    fp = 0
    for i = 1, 5000
      dom = "absent#{i}.nowhere#{i % 11}.invalid"
      in_oracle = oracle[tostring bin48.truncate xxh64 dom] == true
      continue if in_oracle  -- collision improbable : pas un absent réel
      fp += 1 if lookup48 dom
    assert.is_true fp == 0, "aucun faux positif attendu sur 5000 absents (eu : #{fp})"
