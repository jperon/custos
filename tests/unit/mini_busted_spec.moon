-- tests/unit/mini_busted_spec.moon
-- Régression : un échec de hook (setup / before_each / after_each) doit faire
-- échouer la suite du runner VM (`mini_busted`), et non seulement imprimer un
-- message. Avant correctif, `failed` n'était incrémenté que pour un test en
-- échec : un setup cassé pouvait laisser `mini.run()` renvoyer 0.
--
-- On charge une instance NEUVE de tests/helpers/mini_busted.lua via loadfile :
-- sous le runner VM, l'instance globale conduit la suite en cours et un reset
-- casserait son itération.

loader = assert loadfile "tests/helpers/mini_busted.lua"
mini = loader!

describe "mini_busted — échecs de hooks", ->

  after_each ->
    mini.reset!

  it "un setup en échec fait échouer la suite (code retour 1)", ->
    mini.reset!
    mini.describe "bloc", ->
      mini.setup -> error "fixture absente"
      mini.it "test vert", -> assert.is_true true
    assert.equals 1, mini.run!

  it "un before_each en échec fait échouer la suite (code retour 1)", ->
    mini.reset!
    mini.describe "bloc", ->
      mini.before_each -> error "hook cassé"
      mini.it "test vert", -> assert.is_true true
    assert.equals 1, mini.run!

  it "un after_each en échec fait échouer la suite (code retour 1)", ->
    mini.reset!
    mini.describe "bloc", ->
      mini.after_each -> error "hook cassé"
      mini.it "test vert", -> assert.is_true true
    assert.equals 1, mini.run!
