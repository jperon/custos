-- tests/unit/nft_spec.moon
-- Spec direct de src/nft.moon : run_cmd (succès, échec loggé, tampon d'erreur
-- libnftables, opts.quiet) et cleanup. Le module crée son contexte au
-- chargement : ffi_defs et log sont remplacés le temps du require, puis
-- restaurés (même approche que ip_whitelist_spec).

ffi = require "ffi"

-- Construit un faux libnftables et l'état observable des appels.
-- opts : rc (défaut 0), buffer_error, error_buffer, error_raises.
make_libnft = (opts={}) ->
  state = {
    rc: opts.rc or 0
    cmds: {}
    freed: 0
    buffer_error_calls: 0
  }
  lib = {
    nft_ctx_new: -> {}
    nft_ctx_free: -> state.freed += 1
    nft_run_cmd_from_buffer: (ctx, cmd) ->
      state.cmds[#state.cmds + 1] = cmd
      state.rc
  }
  if opts.buffer_error
    lib.nft_ctx_buffer_error = (ctx) ->
      state.buffer_error_calls += 1
      0
  if opts.error_buffer
    lib.nft_ctx_get_error_buffer = -> ffi.cast "const char*", opts.error_buffer
  if opts.error_raises
    lib.nft_ctx_get_error_buffer = -> error "tampon inaccessible"
  lib, state

-- Faux log qui capture le thunk évalué (comme le stub partagé, mais garde les
-- champs pour les assertions).
make_log = ->
  captured = {}
  {
    log_warn: (thunk) -> captured[#captured + 1] = thunk!
    log_error: (thunk) -> captured[#captured + 1] = thunk!
  }, captured

-- Charge nft avec ffi_defs/libnft et log fournis, puis restaure les stubs
-- partagés. Le module conserve la référence à `lib`, donc `state.rc` reste
-- pilotable après le chargement.
load_nft = (lib, log) ->
  saved_defs = package.loaded["ffi_defs"]
  saved_log = package.loaded["log"]
  saved_mod = package.loaded["nft"]
  package.loaded["ffi_defs"] = { :ffi, libc: ffi.C, libnfq: {}, libnft: lib }
  package.loaded["log"] = log if log
  package.loaded["nft"] = nil
  mod = require "nft"
  package.loaded["ffi_defs"] = saved_defs
  package.loaded["log"] = saved_log
  package.loaded["nft"] = saved_mod
  mod

describe "nft.run_cmd", ->
  nft = nil
  lib = nil
  state = nil
  captured = nil

  before_each ->
    lib, state = make_libnft { rc: 0, buffer_error: true }
    log, captured = make_log!
    nft = load_nft lib, log

  it "retourne true sans log quand la commande réussit", ->
    ok, err = nft.run_cmd "add table bridge test"
    assert.is_true ok
    assert.is_nil err
    assert.equals 0, #captured
    assert.equals "add table bridge test", state.cmds[1]

  it "retourne false et logge nft_cmd_failed en cas d'échec", ->
    state.rc = 1
    ok, err = nft.run_cmd "mauvaise commande"
    assert.is_false ok
    assert.is_nil err
    assert.equals 1, #captured
    f = captured[1]
    assert.equals "nft_cmd_failed", f.action
    assert.equals "mauvaise commande", f.cmd
    assert.equals 1, f.rc
    assert.equals "", f.nft_err
    assert.equals "", f.transient
    assert.is_number f.ts

  it "expose le tampon d'erreur et marque transient=resource_busy", ->
    lib2, state2 = make_libnft { rc: 1, buffer_error: true, error_buffer: "Resource busy" }
    log2, captured2 = make_log!
    nft2 = load_nft lib2, log2
    ok, err = nft2.run_cmd "add element bridge …"
    assert.is_false ok
    assert.equals "Resource busy", err
    assert.equals 1, #captured2
    assert.equals "Resource busy", captured2[1].nft_err
    assert.equals "resource_busy", captured2[1].transient

  it "traite un tampon d'erreur vide comme absent", ->
    lib2, state2 = make_libnft { rc: 1, buffer_error: true, error_buffer: "" }
    log2, captured2 = make_log!
    nft2 = load_nft lib2, log2
    ok, err = nft2.run_cmd "bad"
    assert.is_false ok
    assert.is_nil err
    assert.equals "", captured2[1].nft_err

  it "retombe sur nft_err vide si nft_ctx_buffer_error a échoué", ->
    lib2, state2 = make_libnft { rc: 1 }  -- pas de nft_ctx_buffer_error
    log2, captured2 = make_log!
    nft2 = load_nft lib2, log2
    ok, err = nft2.run_cmd "bad"
    assert.is_false ok
    assert.is_nil err
    assert.equals "", captured2[1].nft_err

  it "ignore une exception de nft_ctx_get_error_buffer", ->
    lib2, state2 = make_libnft { rc: 1, buffer_error: true, error_raises: true }
    log2, captured2 = make_log!
    nft2 = load_nft lib2, log2
    ok, err = nft2.run_cmd "bad"
    assert.is_false ok
    assert.is_nil err
    assert.equals "", captured2[1].nft_err

  it "opts.quiet supprime le log mais conserve le retour d'échec", ->
    state.rc = 1
    ok, err = nft.run_cmd "bad", { quiet: true }
    assert.is_false ok
    assert.is_nil err
    assert.equals 0, #captured
    assert.equals 1, #state.cmds

describe "nft.cleanup", ->
  it "libère le contexte", ->
    lib, state = make_libnft { buffer_error: true }
    log = make_log!
    nft = load_nft lib, log
    assert.equals 0, state.freed
    nft.cleanup!
    assert.equals 1, state.freed

describe "nft au chargement", ->
  it "lève si nft_ctx_new échoue", ->
    saved_defs = package.loaded["ffi_defs"]
    saved_mod = package.loaded["nft"]
    package.loaded["ffi_defs"] = {
      :ffi
      libc: ffi.C
      libnfq: {}
      libnft: { nft_ctx_new: -> nil }
    }
    package.loaded["nft"] = nil
    ok, err = pcall require, "nft"
    package.loaded["ffi_defs"] = saved_defs
    package.loaded["nft"] = saved_mod
    assert.is_false ok
    assert.truthy tostring(err)\find "nft_ctx_new() échoué", 1, true
