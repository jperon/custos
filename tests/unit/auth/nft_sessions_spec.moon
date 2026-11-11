-- tests/unit/auth/nft_sessions_spec.moon
-- Spec direct de src/auth/nft_sessions.moon : chaque fonction exportée doit
-- émettre la commande nft attendue via libnftables (FFI stubbée) et propager
-- le code retour. Le module crée son contexte au chargement : ffi_defs est
-- remplacé le temps du require, puis le stub partagé de busted_setup restauré
-- (même approche que ip_whitelist_spec).

ffi = require "ffi"

nft_rc = 0
cmds = {}
free_calls = 0
ctx_flags = nil

nft_stub = {
  nft_ctx_new: (flags) ->
    ctx_flags = flags
    {}
  nft_run_cmd_from_buffer: (ctx, cmd) ->
    cmds[#cmds + 1] = cmd
    nft_rc
  nft_ctx_free: -> free_calls += 1
}

-- Charge le module avec la FFI stubbée, puis restaure l'état partagé : le
-- module garde la référence à nft_stub, donc nft_rc reste pilotable après coup.
load_sessions = ->
  saved_defs = package.loaded["ffi_defs"]
  saved_mod = package.loaded["auth.nft_sessions"]
  package.loaded["ffi_defs"] = { :ffi, libc: ffi.C, libnfq: {}, libnft: nft_stub }
  package.loaded["auth.nft_sessions"] = nil
  mod = require "auth.nft_sessions"
  package.loaded["ffi_defs"] = saved_defs
  package.loaded["auth.nft_sessions"] = saved_mod
  mod

reset = ->
  nft_rc = 0
  cmds = {}
  free_calls = 0
  ctx_flags = nil

config = require "config"

describe "auth.nft_sessions", ->
  sess = nil

  before_each ->
    reset!
    sess = load_sessions!

  it "crée le contexte nft avec les drapeaux 0 (NFT_CTX_DEFAULT)", ->
    assert.equals 0, ctx_flags

  it "add_authenticated4 émet add element + timeout et retourne true", ->
    ok = sess.add_authenticated4 "10.0.0.7", 120
    assert.is_true ok
    assert.equals "add element #{config.nft.family} #{config.nft.table} authenticated_ips { 10.0.0.7 timeout 120s }", cmds[1]

  it "add_authenticated4 retourne false si nft échoue", ->
    nft_rc = 1
    assert.is_false sess.add_authenticated4 "10.0.0.7", 120
    assert.equals 1, #cmds

  it "del_authenticated4 émet delete element sans timeout", ->
    assert.is_true sess.del_authenticated4 "10.0.0.7"
    assert.equals "delete element #{config.nft.family} #{config.nft.table} authenticated_ips { 10.0.0.7 }", cmds[1]

  it "add_authenticated6 émet add element dans authenticated_ips6", ->
    assert.is_true sess.add_authenticated6 "fd00::7", 60
    assert.equals "add element #{config.nft.family} #{config.nft.table} authenticated_ips6 { fd00::7 timeout 60s }", cmds[1]

  it "del_authenticated6 émet delete element dans authenticated_ips6", ->
    assert.is_true sess.del_authenticated6 "fd00::7"
    assert.equals "delete element #{config.nft.family} #{config.nft.table} authenticated_ips6 { fd00::7 }", cmds[1]

  it "add_authenticated_mac émet add element dans authenticated_macs", ->
    assert.is_true sess.add_authenticated_mac "aa:bb:cc:dd:ee:ff", 300
    assert.equals "add element #{config.nft.family} #{config.nft.table} authenticated_macs { aa:bb:cc:dd:ee:ff timeout 300s }", cmds[1]

  it "del_authenticated_mac émet delete element dans authenticated_macs", ->
    assert.is_true sess.del_authenticated_mac "aa:bb:cc:dd:ee:ff"
    assert.equals "delete element #{config.nft.family} #{config.nft.table} authenticated_macs { aa:bb:cc:dd:ee:ff }", cmds[1]

  it "run_nft traduit rc == 0 en true et rc != 0 en false", ->
    assert.is_true sess.run_nft "list ruleset"
    nft_rc = -1
    assert.is_false sess.run_nft "list ruleset"
    assert.equals 2, #cmds

  it "cleanup libère le contexte une fois", ->
    assert.equals 0, free_calls
    sess.cleanup!
    assert.equals 1, free_calls

  describe "dispatch IPv4/IPv6", ->
    it "add_authenticated route une IPv4 vers authenticated_ips", ->
      assert.is_true sess.add_authenticated "10.0.0.7", 30
      assert.equals "add element #{config.nft.family} #{config.nft.table} authenticated_ips { 10.0.0.7 timeout 30s }", cmds[1]

    it "add_authenticated route une IPv6 vers authenticated_ips6", ->
      assert.is_true sess.add_authenticated "fd00::7", 30
      assert.equals "add element #{config.nft.family} #{config.nft.table} authenticated_ips6 { fd00::7 timeout 30s }", cmds[1]

    it "del_authenticated route une IPv4 vers authenticated_ips", ->
      assert.is_true sess.del_authenticated "10.0.0.7"
      assert.equals "delete element #{config.nft.family} #{config.nft.table} authenticated_ips { 10.0.0.7 }", cmds[1]

    it "del_authenticated route une IPv6 vers authenticated_ips6", ->
      assert.is_true sess.del_authenticated "fd00::7"
      assert.equals "delete element #{config.nft.family} #{config.nft.table} authenticated_ips6 { fd00::7 }", cmds[1]

describe "auth.nft_sessions au chargement", ->
  it "lève si nft_ctx_new échoue", ->
    saved_defs = package.loaded["ffi_defs"]
    saved_mod = package.loaded["auth.nft_sessions"]
    package.loaded["ffi_defs"] = {
      :ffi
      libc: ffi.C
      libnfq: {}
      libnft: { nft_ctx_new: -> nil }
    }
    package.loaded["auth.nft_sessions"] = nil
    ok, err = pcall require, "auth.nft_sessions"
    package.loaded["ffi_defs"] = saved_defs
    package.loaded["auth.nft_sessions"] = saved_mod
    assert.is_false ok
    assert.truthy tostring(err)\find "nft_ctx_new() failed in auth worker", 1, true
