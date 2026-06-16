-- tests/unit/nft_marks_spec.moon

bit = require "bit"
marks = require "nft_marks"

describe "nft_marks", ->
  it "réserve une mark haute pour le routage SNI → worker_reject", ->
    assert.are.equal 0x02000000, marks.REJECT_MARK
    assert.are.equal "0x02000000", marks.REJECT_MARK_HEX

  it "n'entre pas en collision avec les plages documentées", ->
    assert.are.equal 0, bit.band marks.REJECT_MARK, 0x00000fff  -- VLAN id
    assert.are.equal 0, bit.band marks.REJECT_MARK, 0x00010000  -- auth mark
    assert.is_true marks.REJECT_MARK > 0x00004000              -- marks de règles compilées
