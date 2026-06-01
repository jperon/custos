-- tests/unit/tools/descriptions_spec.moon
-- Tests du module de descriptions de catégories de tools/classifier/descriptions.moon
-- (table pure name → description injectée dans le prompt de classification).
--
-- Le module vit dans tools/classifier/ (outil autonome non compilé par `make all`).
-- On charge donc sa SOURCE .moon à la volée via le runtime moonscript déjà
-- présent dans lua/ (cf. LUA_PATH des tests), sans artefact .lua à committer.

descriptions = do
  base = require "moonscript.base"
  loader = assert base.loadfile "tools/classifier/descriptions.moon"
  loader!

describe "descriptions", ->
  it "est une table de chaînes non vides", ->
    assert.is_table descriptions
    n = 0
    for cat, desc in pairs descriptions
      n += 1
      assert.is_string cat
      assert.is_string desc
      assert.is_true #desc > 0, "description vide pour #{cat}"
    assert.is_true n > 0

  it "distingue art_nude de la pornographie", ->
    d = descriptions.art_nude
    assert.is_string d
    assert.truthy d\lower!\find "not pornography", 1, true

  it "couvre les catégories existantes du dépôt", ->
    fh = io.popen "ls -1 lists/*.txt 2>/dev/null"
    missing = {}
    if fh
      for line in fh\lines!
        cat = line\match "([^/]+)%.txt$"
        missing[#missing + 1] = cat if cat and not descriptions[cat]
      fh\close!
    assert.same {}, missing
