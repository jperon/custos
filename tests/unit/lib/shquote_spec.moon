-- tests/unit/lib/shquote_spec.moon
{ :shquote } = require "lib.shquote"

describe "shquote", ->
  it "entoure une valeur simple de quotes simples", ->
    assert.equals "'br0'", shquote "br0"

  it "neutralise une quote simple interne", ->
    -- a'b → 'a'\''b'
    assert.equals "'a'\\''b'", shquote "a'b"

  it "neutralise une tentative d'injection shell", ->
    -- La charge utile entière reste un seul argument littéral, quotes comprises.
    out = shquote "/tmp/'; rm -rf / #"
    assert.equals "'/tmp/'\\''; rm -rf / #'", out

  it "convertit les valeurs non-string", ->
    assert.equals "'2048'", shquote 2048

  it "gère la chaîne vide", ->
    assert.equals "''", shquote ""
