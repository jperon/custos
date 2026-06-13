-- tests/unit/lib/ttl_set_spec.moon
package.path = "src/?.lua;src/?/init.lua;src/?/?.lua;lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path

S = require "lib.ttl_set"

describe "lib.ttl_set", ->
  -- Horloge contrôlable pour tester l'expiration.
  make_clock = ->
    t = { v: 1000 }
    t, -> t.v

  it "add/has/remove de base", ->
    _, clock = make_clock!
    s = S.new 16, 60, clock
    assert.is_false s.has "a"
    s.add "a"
    assert.is_true s.has "a"
    assert.equals 1, s.size!
    s.remove "a"
    assert.is_false s.has "a"
    assert.equals 0, s.size!

  it "expire après le TTL", ->
    t, clock = make_clock!
    s = S.new 16, 30, clock
    s.add "x"
    t.v += 29
    assert.is_true s.has "x"
    t.v += 2   -- dépasse 30
    assert.is_false s.has "x"
    assert.equals 0, s.size!   -- expiration paresseuse décrémente la taille

  it "rafraîchit l'expiration sur re-add", ->
    t, clock = make_clock!
    s = S.new 16, 30, clock
    s.add "x"
    t.v += 20
    s.add "x"          -- réarme à t+30
    t.v += 20          -- 40s depuis le 1er add, 20s depuis le 2e
    assert.is_true s.has "x"

  it "borne la taille (vidage dur quand plein de non-expirés)", ->
    _, clock = make_clock!
    s = S.new 2, 60, clock
    s.add "a"
    s.add "b"
    assert.equals 2, s.size!
    s.add "c"          -- plein, rien à élaguer → vidage puis insertion
    assert.is_true s.has "c"
    assert.is_true s.size! <= 2

  it "élague les expirés avant le vidage dur", ->
    t, clock = make_clock!
    s = S.new 2, 30, clock
    s.add "a"
    s.add "b"
    t.v += 31          -- a et b expirés
    s.add "c"          -- l'élagage libère la place, pas de vidage
    assert.is_true s.has "c"
    assert.equals 1, s.size!

  it "ignore une clé nil", ->
    _, clock = make_clock!
    s = S.new 16, 60, clock
    assert.is_false s.has nil
    s.add nil
    s.remove nil
    assert.equals 0, s.size!
