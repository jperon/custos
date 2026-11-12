-- tests/unit/lib/lowmem_spec.moon
-- Tests unitaires du module lib.lowmem (détection RAM faible + réduction NFQUEUE).

package.path = "src/?.lua;src/?/init.lua;src/?/?.lua;lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path

lowmem = require "lib.lowmem"

describe "lib.lowmem", ->
  describe "parse_queues", ->
    it "parse un nombre simple", ->
      assert.same { 4 }, lowmem.parse_queues "4"

    it "parse une plage croissante", ->
      assert.same { 0, 1 }, lowmem.parse_queues "0-1"

    it "parse une plage décroissante", ->
      assert.same { 10, 11 }, lowmem.parse_queues "11-10"

    it "parse une liste mixte", ->
      assert.same { 0, 2, 5, 6, 7 }, lowmem.parse_queues "0,2,5-7"

    it "renvoie une table vide pour nil", ->
      assert.same {}, lowmem.parse_queues nil

  describe "is_contiguous_range", ->
    it "accepte un nombre seul et une plage croissante", ->
      assert.is_true lowmem.is_contiguous_range "4"
      assert.is_true lowmem.is_contiguous_range "4-5"
      assert.is_true lowmem.is_contiguous_range " 0-65535 "

    it "refuse une liste avec virgules (syntaxe nft invalide)", ->
      assert.is_false lowmem.is_contiguous_range "4,6"
      assert.is_false lowmem.is_contiguous_range "0,2,5-7"

    it "refuse une plage décroissante ou malformée", ->
      assert.is_false lowmem.is_contiguous_range "5-4"
      assert.is_false lowmem.is_contiguous_range "4-"
      assert.is_false lowmem.is_contiguous_range "abc"
      assert.is_false lowmem.is_contiguous_range nil

  describe "detect", ->
    it "force à true via lowmem=true", ->
      assert.is_true lowmem.detect { lowmem: true }, -> 999999999

    it "force à true via lowmem=\"on\"", ->
      assert.is_true lowmem.detect { lowmem: "on" }, -> 999999999

    it "force à false via lowmem=false même si RAM faible", ->
      assert.is_false lowmem.detect { lowmem: false }, -> 1024

    it "force à false via lowmem=\"off\"", ->
      assert.is_false lowmem.detect { lowmem: "off" }, -> 1024

    it "autodétecte true sous le seuil par défaut (128 Mo)", ->
      assert.is_true lowmem.detect {}, -> 65536  -- 64 Mo

    it "autodétecte false au-dessus du seuil par défaut", ->
      assert.is_false lowmem.detect {}, -> 262144  -- 256 Mo

    it "respecte un seuil personnalisé", ->
      assert.is_true lowmem.detect { lowmem_threshold_kb: 262144 }, -> 131072

    it "renvoie false si la RAM est illisible (0)", ->
      assert.is_false lowmem.detect {}, -> 0

  describe "resolve_pending_max", ->
    it "une valeur explicite positive prime sur le profil", ->
      assert.equals 1234, lowmem.resolve_pending_max 1234, false
      assert.equals 1234, lowmem.resolve_pending_max "1234", true

    it "absente, nulle ou invalide : défaut du profil", ->
      assert.equals 20000, lowmem.resolve_pending_max nil, false
      assert.equals 5000,  lowmem.resolve_pending_max nil, true
      assert.equals 20000, lowmem.resolve_pending_max 0, false
      assert.equals 5000,  lowmem.resolve_pending_max "abc", true
      assert.equals 5000,  lowmem.resolve_pending_max -5, true

    it "arrondit une valeur décimale explicite", ->
      assert.equals 42, lowmem.resolve_pending_max 42.7, false

    it "expose les deux bornes du profil", ->
      assert.equals 20000, lowmem.PENDING_MAX_DEFAULT
      assert.equals 5000,  lowmem.LOWMEM_PENDING_MAX

  describe "read_mem_total_kb", ->
    it "renvoie 0 pour un chemin inexistant", ->
      assert.equals 0, lowmem.read_mem_total_kb "tmp/inexistant-meminfo-xyz"

    it "lit MemTotal depuis un fichier fourni", ->
      path = "tmp/fake-meminfo-#{os.time!}"
      f = io.open path, "w"
      f\write "MemTotal:       123456 kB\nMemFree:  1000 kB\n"
      f\close!
      assert.equals 123456, lowmem.read_mem_total_kb path
      os.remove path

  describe "collapse_nfqueue", ->
    it "réduit chaque plage à sa première file et résume", ->
      nfq = { questions: "0-1", responses: "4", captive: "20", reject: "10-11" }
      summary = lowmem.collapse_nfqueue nfq
      assert.equals "0", nfq.questions
      assert.equals "4", nfq.responses
      assert.equals "20", nfq.captive
      assert.equals "10", nfq.reject
      assert.equals "0-1 → 0", summary.questions
      assert.equals "10-11 → 10", summary.reject
      assert.is_nil summary.responses

    it "ne touche pas les clés hors liste (auth/sni/sip)", ->
      nfq = { questions: "0-1", auth: "5-7", sni: "6", sip: "12" }
      lowmem.collapse_nfqueue nfq
      assert.equals "5-7", nfq.auth
