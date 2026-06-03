-- tests/unit/lib/os_constants_spec.moon
-- Vérifie que os_constants retourne les valeurs correctes pour l'architecture
-- courante (x86/x86_64 en CI), et que toutes les constantes sont cohérentes.

describe "lib.os_constants", ->
  c = require "lib.os_constants"

  it "exporte toutes les constantes attendues", ->
    for k in *{"O_NONBLOCK","O_APPEND","O_CREAT","O_EXCL",
               "SIG_BLOCK","SOL_SOCKET","SO_REUSEADDR","SO_REUSEPORT"}
      assert.not_nil c[k], "constante manquante : #{k}"
      assert.is_number c[k]

  -- Sur x86/x86_64 (architecture de la CI), les valeurs sont connues.
  it "retourne les valeurs x86 correctes en CI", ->
    assert.equals 0x800, c.O_NONBLOCK,   "O_NONBLOCK x86"
    assert.equals 0x400, c.O_APPEND,     "O_APPEND x86"
    assert.equals 0x40,  c.O_CREAT,      "O_CREAT x86"
    assert.equals 0x80,  c.O_EXCL,       "O_EXCL x86"
    assert.equals 0,     c.SIG_BLOCK,    "SIG_BLOCK x86"
    assert.equals 1,     c.SOL_SOCKET,   "SOL_SOCKET x86"
    assert.equals 2,     c.SO_REUSEADDR, "SO_REUSEADDR x86"
    assert.equals 15,    c.SO_REUSEPORT, "SO_REUSEPORT x86"

  it "les constantes sont toutes des entiers positifs non nuls (sauf SIG_BLOCK qui peut être 0)", ->
    for k, v in pairs c
      if k != "SIG_BLOCK"
        assert.is_true v > 0, "#{k} doit être > 0, obtenu #{v}"
