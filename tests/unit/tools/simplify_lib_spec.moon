-- tests/unit/tools/simplify_lib_spec.moon
-- Tests de la logique PURE de tools/classifier/simplify_lib.moon
-- (génération de parents candidats, filtre maximal, plan de repli).
--
-- Le module vit dans tools/classifier/ (outil autonome non compilé par `make all`).
-- On charge donc sa SOURCE .moon à la volée via le runtime moonscript déjà
-- présent dans lua/ (cf. LUA_PATH des tests), sans artefact .lua à committer.

slib = do
  base = require "moonscript.base"
  loader = assert base.loadfile "tools/classifier/simplify_lib.moon"
  loader!

set_size = (s) ->
  n = 0
  n += 1 for _ in pairs s
  n

has = (t, v) ->
  for x in *t
    return true if x == v
  false

describe "simplify_lib", ->
  describe "nlabels", ->
    it "compte les labels", ->
      assert.equal 3, slib.nlabels "a.b.com"
      assert.equal 2, slib.nlabels "userapi.com"
      assert.equal 1, slib.nlabels "com"

  describe "is_ancestor", ->
    it "reconnaît un ancêtre strict", ->
      assert.is_true slib.is_ancestor "userapi.com", "sun1-13.userapi.com"
      assert.is_true slib.is_ancestor "foo.net", "a.b.foo.net"

    it "rejette l'égalité et les faux suffixes", ->
      assert.is_false slib.is_ancestor "userapi.com", "userapi.com"
      assert.is_false slib.is_ancestor "api.com", "userapi.com"

  describe "suffixes", ->
    it "renvoie les suffixes ≥ 2 labels, domaine inclus, TLD exclu", ->
      suf = slib.suffixes "a.b.c.com"
      assert.is_true has suf, "a.b.c.com"
      assert.is_true has suf, "b.c.com"
      assert.is_true has suf, "c.com"
      assert.is_false has suf, "com"

    it "ne renvoie rien d'exploitable pour un TLD seul", ->
      assert.same {}, slib.suffixes "com"

  describe "redundant", ->
    it "supprime les sous-domaines d'un parent présent dans la liste", ->
      doms = {
        "userapi.com", "sun1-13.userapi.com", "sun1-16.userapi.com"
        "other.com"
      }
      drop = slib.redundant doms
      assert.equal 2, set_size drop
      assert.is_true drop["sun1-13.userapi.com"]
      assert.is_true drop["sun1-16.userapi.com"]
      assert.is_nil drop["userapi.com"]
      assert.is_nil drop["other.com"]

    it "ne supprime rien si le parent est absent", ->
      doms = { "a.userapi.com", "b.userapi.com", "c.userapi.com" }
      assert.equal 0, set_size slib.redundant doms

    it "gère les ancêtres à plusieurs niveaux", ->
      doms = { "foo.net", "a.b.foo.net", "b.foo.net" }
      drop = slib.redundant doms
      assert.is_true drop["a.b.foo.net"]
      assert.is_true drop["b.foo.net"]
      assert.is_nil drop["foo.net"]

  describe "candidates", ->
    it "propose le parent d'une grappe de sous-domaines", ->
      doms = ["sun1-#{i}.userapi.com" for i = 1, 5]
      cands = slib.candidates doms, 3
      assert.equal 1, #cands
      assert.equal "userapi.com", cands[1].parent
      assert.equal 5, cands[1].count

    it "respecte le seuil min_children", ->
      doms = { "a.userapi.com", "b.userapi.com" }
      assert.equal 0, #slib.candidates doms, 3
      assert.equal 1, #slib.candidates doms, 2

    it "ne garde que le parent maximal (le plus large)", ->
      doms = { "a.x.foo.net", "b.x.foo.net", "c.x.foo.net", "d.foo.net" }
      cands = slib.candidates doms, 3
      assert.equal 1, #cands
      assert.equal "foo.net", cands[1].parent

    it "ignore un domaine isolé sans sous-domaine à replier", ->
      -- userapi.com seul (pas de sous-domaine) ne doit pas se proposer lui-même.
      doms = { "userapi.com", "other.com", "third.org" }
      assert.equal 0, #slib.candidates doms, 1

    it "trie par couverture décroissante", ->
      doms = {
        "a.big.com", "b.big.com", "c.big.com", "d.big.com"
        "a.small.net", "b.small.net", "c.small.net"
      }
      cands = slib.candidates doms, 3
      assert.equal "big.com", cands[1].parent
      assert.equal "small.net", cands[2].parent

  describe "fold_plan", ->
    it "supprime parent + sous-domaines, ajoute le parent", ->
      doms = {
        "sun1-13.userapi.com", "sun1-16.userapi.com", "userapi.com"
        "mail.google.com", "www.google.com"
      }
      drop, add = slib.fold_plan doms, { "userapi.com": true }
      assert.equal 3, set_size drop          -- 2 sous-domaines + le parent lui-même
      assert.is_true drop["sun1-13.userapi.com"]
      assert.is_true drop["userapi.com"]
      assert.is_nil drop["mail.google.com"]
      assert.same { "userapi.com" }, add

    it "gère plusieurs parents approuvés", ->
      doms = { "a.x.com", "b.x.com", "a.y.net", "b.y.net" }
      drop, add = slib.fold_plan doms, { "x.com": true, "y.net": true }
      assert.equal 4, set_size drop
      assert.same { "x.com", "y.net" }, add
