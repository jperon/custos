-- tests/unit/ip_whitelist_spec.moon
-- Spec direct de src/ip_whitelist.moon : init (flush des deux sets puis
-- répartition v4/v6), cas vides et cleanup.
--
-- Le module crée un contexte libnftables au chargement : stub ffi_defs le
-- temps du require, puis restauration du stub partagé de busted_setup. Le
-- module conserve la référence à la table libnft capturée, donc `nft_rc`
-- reste pilotable après coup sans fuiter vers les autres specs.

ffi = require "ffi"
nft_rc = 0
nft_cmds = {}
free_calls = 0

nft_stub = {
  nft_ctx_new: -> {}
  nft_ctx_free: -> free_calls += 1
  nft_run_cmd_from_buffer: (ctx, cmd) ->
    nft_cmds[#nft_cmds + 1] = cmd
    nft_rc
}

orig_ffi_defs = package.loaded["ffi_defs"]
package.loaded["ffi_defs"] = {
  :ffi
  libc: ffi.C
  libnfq: {}
  libnft: nft_stub
}
package.loaded["ip_whitelist"] = nil
ip_whitelist = require "ip_whitelist"
if orig_ffi_defs
  package.loaded["ffi_defs"] = orig_ffi_defs
else
  package.loaded["ffi_defs"] = nil

config = require "config"

reset = ->
  nft_cmds = {}
  nft_rc = 0
  free_calls = 0

describe "ip_whitelist.init", ->
  before_each reset

  it "purge les deux sets puis ajoute les entrées v4 et v6", ->
    ip_whitelist.init { "10.0.0.1", "192.168.0.0/16", "2a01:db8::1", "fc00::/7" }
    assert.equals 4, #nft_cmds
    assert.truthy nft_cmds[1]\find "flush set bridge dns-filter-bridge ip4_dest_whitelist", 1, true
    assert.truthy nft_cmds[2]\find "flush set bridge dns-filter-bridge ip6_dest_whitelist", 1, true
    assert.truthy nft_cmds[3]\find "add element bridge dns-filter-bridge ip4_dest_whitelist { 10.0.0.1, 192.168.0.0/16 }", 1, true
    assert.truthy nft_cmds[4]\find "add element bridge dns-filter-bridge ip6_dest_whitelist { 2a01:db8::1, fc00::/7 }", 1, true

  it "supprime les espaces internes des entrées", ->
    ip_whitelist.init { " 10.0.0.1 ", "fc00: :1" }
    assert.truthy nft_cmds[3]\find "{ 10.0.0.1 }", 1, true
    assert.truthy nft_cmds[4]\find "{ fc00::1 }", 1, true

  it "n'ajoute que la famille présente", ->
    ip_whitelist.init { "10.0.0.1" }
    assert.equals 3, #nft_cmds
    assert.truthy nft_cmds[3]\find "ip4_dest_whitelist { 10.0.0.1 }", 1, true

  it "table vide ou nil → seulement les deux flush", ->
    ip_whitelist.init {}
    assert.equals 2, #nft_cmds
    reset!
    ip_whitelist.init nil
    assert.equals 2, #nft_cmds

  it "entrées vides ou blanches ignorées", ->
    ip_whitelist.init { "", "   ", "\t" }
    assert.equals 2, #nft_cmds

  it "échec nft (rc ≠ 0) → init ne lève pas et continue", ->
    nft_rc = 1
    ip_whitelist.init { "10.0.0.1", "fc00::1" }
    assert.equals 4, #nft_cmds

describe "ip_whitelist.cleanup", ->
  before_each reset

  it "libère le contexte nftables", ->
    ip_whitelist.cleanup!
    assert.equals 1, free_calls
