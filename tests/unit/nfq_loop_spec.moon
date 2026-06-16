-- tests/unit/nfq_loop_spec.moon
-- Couverture des helpers de verdict NFQUEUE, dont le verdict marqué utilisé
-- pour router les refus SNI vers worker_reject.

ffi = require "ffi"

orig_ffi_defs = package.loaded["ffi_defs"]
orig_nfq_loop = package.loaded["nfq_loop"]
fake_calls = {}
package.loaded["ffi_defs"] = {
  :ffi
  libc: ffi.C
  libnfq: {
    nfq_set_verdict: (qh, id, verdict, datalen, buf) ->
      fake_calls[#fake_calls + 1] = { fn: "nfq_set_verdict", :qh, :id, :verdict, :datalen, buf_is_nil: buf == nil }
      0
    nfq_set_verdict2: (qh, id, verdict, mark, datalen, buf) ->
      fake_calls[#fake_calls + 1] = { fn: "nfq_set_verdict2", :qh, :id, :verdict, :mark, :datalen, buf_is_nil: buf == nil }
      0
  }
  libnft: {}
}
package.loaded["nfq_loop"] = nil

nfq = require "nfq_loop"

describe "nfq_loop verdict helpers", ->
  teardown ->
    package.loaded["ffi_defs"] = orig_ffi_defs
    package.loaded["nfq_loop"] = orig_nfq_loop

  before_each ->
    while #fake_calls > 0
      table.remove fake_calls

  it "set_verdict_marked appelle nfq_set_verdict2 avec mark et sans payload", ->
    rc = nfq.set_verdict_marked nil, 42, nfq.NF_ACCEPT, 0x02000000
    assert.are.equal 0, rc
    assert.are.equal 1, #fake_calls
    call = fake_calls[1]
    assert.are.equal "nfq_set_verdict2", call.fn
    assert.are.equal 42, call.id
    assert.are.equal nfq.NF_ACCEPT, call.verdict
    assert.are.equal 0x02000000, call.mark
    assert.are.equal 0, call.datalen
    assert.is_true call.buf_is_nil

  it "set_verdict_marked transmet un payload de remplacement si fourni", ->
    rc = nfq.set_verdict_marked nil, 7, nfq.NF_ACCEPT, 0x02000000, "abc"
    assert.are.equal 0, rc
    call = fake_calls[1]
    assert.are.equal "nfq_set_verdict2", call.fn
    assert.are.equal 3, call.datalen
    assert.is_false call.buf_is_nil

  it "set_verdict_marked normalise un retour positif (bytes-sent) en 0", ->
    -- Régression : libnetfilter_queue renvoie parfois le nombre d'octets
    -- émis (>0) au lieu de 0. Voir err=40 dans les logs SNI.
    package.loaded["ffi_defs"].libnfq.nfq_set_verdict2 = (qh, id, verdict, mark, datalen, buf) ->
      fake_calls[#fake_calls + 1] = { fn: "nfq_set_verdict2", :qh, :id, :verdict, :mark, :datalen, buf_is_nil: buf == nil }
      40
    package.loaded["nfq_loop"] = nil
    nfq2 = require "nfq_loop"
    rc = nfq2.set_verdict_marked nil, 1, nfq2.NF_ACCEPT, 0x02000000
    assert.are.equal 0, rc
