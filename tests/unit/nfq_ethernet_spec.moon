-- tests/unit/nfq_ethernet_spec.moon
-- T3 : extraction L2 (MAC source, VLAN) depuis les métadonnées NFQUEUE.
-- ffi_defs est stubbé localement (aucune libnetfilter_queue réelle) et restauré.

ffi = require "ffi"

orig_defs = package.loaded["ffi_defs"]
orig_eth  = package.loaded["nfq/ethernet"]

state = {}
package.loaded["ffi_defs"] = {
  :ffi
  libc: ffi.C
  libnfq: {
    nfq_get_packet_hw: -> state.hw
    nfq_get_indev:     -> state.indev or 0
    nfq_get_nfmark:    -> state.mark or 0
  }
}
package.loaded["nfq/ethernet"] = nil
eth = require "nfq/ethernet"

hw_bytes = (b1, b2, b3, b4, b5, b6) ->
  { hw_addrlen: 6, hw_addr: ffi.new("uint8_t[6]", b1, b2, b3, b4, b5, b6) }

describe "nfq/ethernet.get_l2", ->
  teardown ->
    package.loaded["ffi_defs"] = orig_defs
    package.loaded["nfq/ethernet"] = orig_eth

  before_each ->
    state = {}

  it "lit la MAC source depuis nfq_get_packet_hw", ->
    state.hw = hw_bytes 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
    l2 = eth.get_l2 nil
    assert.equals "aa:bb:cc:dd:ee:ff", l2.mac_src
    assert.equals "\170\187\204\221\238\255", l2.mac_raw
    assert.equals "unknown", l2.mac_dst

  it "retourne une MAC inconnue quand hw est absent (paquet OUTPUT)", ->
    state.hw = nil
    l2 = eth.get_l2 nil
    assert.equals "unknown", l2.mac_src
    assert.equals "\0\0\0\0\0\0", l2.mac_raw

  it "ignore un hw_addrlen nul", ->
    state.hw = { hw_addrlen: 0, hw_addr: ffi.new("uint8_t[6]", 1, 2, 3, 4, 5, 6) }
    l2 = eth.get_l2 nil
    assert.equals "unknown", l2.mac_src
    assert.equals "\0\0\0\0\0\0", l2.mac_raw

  it "lit l'index d'entrée", ->
    state.indev = 7
    l2 = eth.get_l2 nil
    assert.equals 7, l2.in_ifindex

  it "mark nul → pas de VLAN", ->
    state.mark = 0
    l2 = eth.get_l2 nil
    assert.is_nil l2.vlan

  it "mark non nul → VLAN", ->
    state.mark = 4096
    l2 = eth.get_l2 nil
    assert.equals 4096, l2.vlan
