-- tests/unit/lib/filelock_spec.moon
-- Tests de lib.filelock : restitution exacte des valeurs de retour de fn
-- (y compris nil en tête), relance de l'erreur et libération du verrou.

{ :with_lock } = require "lib.filelock"

LOCK = "tmp/filelock_spec.lock"

describe "lib.filelock", ->

  after_each ->
    os.remove LOCK

  it "retourne nil, message quand fn retourne nil, \"e\"", ->
    r1, r2 = with_lock LOCK, -> nil, "e"
    assert.is_nil r1
    assert.equals "e", r2

  it "retourne false quand fn retourne false", ->
    r1, r2 = with_lock LOCK, -> false
    assert.is_false r1
    assert.is_nil r2

  it "retourne les trois valeurs de fn", ->
    r1, r2, r3 = with_lock LOCK, -> "a", nil, "c"
    assert.equals "a", r1
    assert.is_nil r2
    assert.equals "c", r3

  it "relance l'erreur de fn et libère le verrou", ->
    ok, err = pcall with_lock, LOCK, -> error "boom"
    assert.is_false ok
    assert.truthy tostring(err)\find "boom", 1, true
    -- Le verrou doit être relâché : un second passage sur le même chemin
    -- ne bloque pas et rend la valeur de fn.
    assert.equals "ok", with_lock LOCK, -> "ok"
