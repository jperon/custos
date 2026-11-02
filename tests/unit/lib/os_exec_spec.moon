-- tests/unit/lib/os_exec_spec.moon
-- Tests de lib.os_exec : normalisation du retour de os.execute pour les deux
-- sémantiques (Lua 5.1 : code numérique ; Lua 5.2+/LUA52COMPAT : true/nil).

{ :exec_ok } = require "lib.os_exec"

describe "lib.os_exec.exec_ok", ->
  it "accepte 0 (sémantique Lua 5.1 : succès)", ->
    assert.is_true exec_ok 0

  it "accepte true (sémantique Lua 5.2+ : succès)", ->
    assert.is_true exec_ok true

  it "rejette un code non nul (Lua 5.1 : échec)", ->
    assert.is_false exec_ok 1
    assert.is_false exec_ok 127

  it "rejette nil (Lua 5.2+ : échec)", ->
    assert.is_false exec_ok nil

  it "rejette false (défense)", ->
    assert.is_false exec_ok false
