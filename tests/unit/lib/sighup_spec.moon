-- tests/unit/lib/sighup_spec.moon
-- Vérifie le veilleur SIGHUP sans handler asynchrone (signalfd).
--
-- Le dernier cas est le test de non-régression du PANIC « bad callback » :
-- avec un handler installé par ffi.C.signal + callback Lua (ancien
-- src/auth/worker.moon:46), un SIGHUP reçu pendant une boucle chaude JIT
-- faisait sortir le processus en erreur (lj_ccallback.c:726-730), donc tuait
-- tout le processus de test.

describe "lib.sighup", ->
  { :libc } = require "ffi_defs"
  sighup = require "lib.sighup"
  ffi = require "ffi"
  -- busted_setup remplace ffi_defs par un stub : kill n'y est pas déclaré.
  pcall ffi.cdef, "int kill(int pid, int sig);"

  it "expose le numéro de SIGHUP", ->
    assert.equals 1, sighup.SIGHUP

  it "ne signale rien sans signal reçu", ->
    w = sighup.create_watcher!
    assert.is_false w\pending!
    w\close!

  it "signale un SIGHUP puis vide la file", ->
    w = sighup.create_watcher!
    assert.equals 0, libc.kill tonumber(libc.getpid!), sighup.SIGHUP
    assert.is_true w\pending!, "le SIGHUP doit être visible"
    assert.is_false w\pending!, "la file doit être vidée par pending!"
    w\close!

  it "coalesce une rafale en un seul événement", ->
    w = sighup.create_watcher!
    for _ = 1, 50
      libc.kill tonumber(libc.getpid!), sighup.SIGHUP
    assert.is_true w\pending!
    assert.is_false w\pending!
    w\close!

  it "survit à un SIGHUP reçu pendant une boucle chaude JIT", ->
    w = sighup.create_watcher!
    x = 0
    for i = 1, 200000
      x = x + (i % 7)
    assert.equals 0, libc.kill tonumber(libc.getpid!), sighup.SIGHUP
    for i = 1, 200000
      x = x + (i % 7)
    assert.is_true w\pending!
    w\close!
