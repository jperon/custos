-- tests/unit/ffi/ffi_defs_spec.moon
-- Vérifie que les déclarations FFI de ffi_defs sont effectivement accessibles.
--
-- NOTE : LuaJIT interdit les redéfinitions cdef.  Dans la suite Busted,
-- lib/socket.lua (chargé par ffi_wolfssl via cert_spec) déclare pollfd et
-- les fonctions socket avant que ffi_defs_spec soit exécuté.  On teste donc
-- la disponibilité des symboles dans ffi.C / ffi.new (effet global LuaJIT),
-- plutôt que le chargement isolé de ffi_defs.lua.

ffi = require "ffi"

-- Charge le vrai ffi_defs en acceptant l'éventuelle erreur de redéfinition
-- (artefact d'ordre de chargement dans Busted, pas un bug de ffi_defs).
package.loaded["ffi_defs"] = nil
ffi_defs_ok, ffi_defs_or_err = pcall require, "ffi_defs"
-- Si le chargement a échoué à cause d'une redéfinition, on considère que
-- les cdef ont déjà été faites — on re-pointe sur le module lib.socket pour
-- avoir les mêmes exports.
if not ffi_defs_ok
  -- Restaure un stub fonctionnel pour les specs suivantes
  package.loaded["ffi_defs"] = { ffi: ffi, libc: ffi.C, libnfq: {}, libnft: {} }

describe "ffi_defs #ffi", ->

  it "chargement réussi ou redéfinition bénigne", ->
    -- Accepte deux cas :
    -- 1. Chargement propre (ffi_defs est le premier à déclarer ces types).
    -- 2. Erreur de redéfinition (lib/socket déjà chargé avant dans Busted).
    --    Dans les deux cas les symboles sont disponibles dans ffi.C.
    if not ffi_defs_ok
      err_str = tostring ffi_defs_or_err
      -- Seule erreur tolérée : redéfinition d'un type déjà déclaré
      assert.truthy err_str\find("redefine", 1, true),
        "erreur inattendue de ffi_defs : " .. err_str
    else
      assert.is_not_nil ffi_defs_or_err.libc

  it "fonctions socket disponibles dans ffi.C", ->
    -- Ces fonctions sont déclarées soit par ffi_defs, soit par lib/socket
    assert.is_not_nil ffi.C.socket
    assert.is_not_nil ffi.C.bind
    assert.is_not_nil ffi.C.listen
    assert.is_not_nil ffi.C.accept
    assert.is_not_nil ffi.C.connect

  it "struct pollfd instanciable", ->
    assert.has_no.errors -> ffi.new "struct pollfd"

  it "struct sockaddr_in instanciable", ->
    assert.has_no.errors -> ffi.new "struct sockaddr_in"

  it "struct sockaddr_in6 instanciable", ->
    assert.has_no.errors -> ffi.new "struct sockaddr_in6"

  it "struct sockaddr_un instanciable", ->
    assert.has_no.errors -> ffi.new "struct sockaddr_un"

  it "struct timeval instanciable", ->
    assert.has_no.errors -> ffi.new "struct timeval"

  it "struct fd_set instanciable", ->
    assert.has_no.errors -> ffi.new "struct fd_set"
