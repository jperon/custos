-- tests/unit/ipparse/l4/tcp_stream_spec.moon
-- Couverture du défragmenteur TCP générique : feed (segment unique, fragmenté,
-- FIN/RST, payload vide), clear, reset et purge par âge.

{ :new } = require "ipparse.l4.tcp_stream"

describe "ipparse.l4.tcp_stream", ->
  describe "feed (sans prédicat)", ->
    it "rend immédiatement chaque segment porteur de payload", ->
      s = new!
      buf, init_seq, first = s.feed "k", "hello", 0x18, 42
      assert.equals "hello", buf
      assert.equals 42, init_seq
      assert.is_true first

    it "ignore un segment à payload vide", ->
      s = new!
      assert.is_nil s.feed "k", "", 0x10, 1

    it "efface la session sur FIN ou RST", ->
      s = new!
      assert.is_nil s.feed "k", "data", 0x01, 1   -- FIN
      assert.is_nil s.feed "k", "data", 0x04, 1   -- RST

  describe "feed (avec prédicat de complétude)", ->
    -- Complet dès que le buffer atteint la longueur annoncée à l'octet 1.
    complete = (buf) -> #buf >= buf\byte(1)

    it "bufferise tant que le record est incomplet puis le rend", ->
      s = new complete
      -- annonce 6 octets au total
      assert.is_nil s.feed "k", "\6abc", 0x18, 100      -- 4 octets → incomplet
      buf, init_seq, first = s.feed "k", "de", 0x18, 104 -- +2 → 6 octets
      assert.equals "\6abcde", buf
      assert.equals 100, init_seq                         -- seq du 1er segment
      assert.is_false first                               -- pas le 1er segment

    it "auto-efface après complétion (nouveau cycle indépendant)", ->
      s = new complete
      s.feed "k", "\2ab", 0x18, 1                          -- complet (>=2)
      buf, _, first = s.feed "k", "\1x", 0x18, 9
      assert.equals "\1x", buf
      assert.is_true first                                 -- session repartie

  describe "clear / reset", ->
    complete = (buf) -> #buf >= buf\byte(1)

    it "clear oublie une session en cours de buffering", ->
      s = new complete
      s.feed "k", "\9ab", 0x18, 1
      s.clear "k"
      _, _, first = s.feed "k", "\1z", 0x18, 2
      assert.is_true first

    it "reset vide toutes les sessions", ->
      s = new complete
      s.feed "a", "\9xx", 0x18, 1
      s.feed "b", "\9yy", 0x18, 1
      s.reset!
      _, _, fa = s.feed "a", "\1z", 0x18, 2
      _, _, fb = s.feed "b", "\1z", 0x18, 2
      assert.is_true fa
      assert.is_true fb

  describe "purge", ->
    complete = (buf) -> #buf >= buf\byte(1)

    it "supprime les sessions plus vieilles que max_age", ->
      s = new complete
      s.feed "k", "\9ab", 0x18, 1   -- bufferisé (3 < 9)
      s.purge -1                     -- max_age négatif → tout est « trop vieux »
      -- session purgée : la complétion suivante repart comme premier segment
      buf, _, first = s.feed "k", "\2zz", 0x18, 50
      assert.equals "\2zz", buf
      assert.is_true first

    it "conserve les sessions récentes", ->
      s = new complete
      s.feed "k", "\9ab", 0x18, 1
      s.purge 100000                 -- rien d'assez vieux
      -- toujours bufferisée : la complétion garde init_seq du 1er segment
      buf, init_seq, first = s.feed "k", "cdefghi", 0x18, 5
      assert.equals "\9abcdefghi", buf
      assert.equals 1, init_seq
      assert.is_false first
