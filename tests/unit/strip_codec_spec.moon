codec = require "strip_codec"

describe "strip_codec", ->
  it "normalise (casse + point final)", ->
    assert.are.equal codec.normalize("ATM.Outlook.MIRA.tm."), "atm.outlook.mira.tm"

  it "hash stable et identique pour des formes équivalentes", ->
    a = codec.name_hash "atm.outlook.mira.tm.svc.cloud.microsoft"
    b = codec.name_hash "ATM.outlook.mira.tm.svc.cloud.microsoft."
    assert.are.equal 8, #a
    assert.are.equal a, b

  it "hash distinct pour des noms différents", ->
    assert.are_not.equal codec.name_hash("a.example"), codec.name_hash("b.example")

  it "encode/decode round-trip", ->
    msg = codec.encode "atm.outlook.mira.tm.svc.cloud.microsoft", 28
    assert.are.equal codec.STRIP_MSG_SIZE, #msg
    hash8, rr = codec.decode msg
    assert.are.equal codec.name_hash("atm.outlook.mira.tm.svc.cloud.microsoft"), hash8
    assert.are.equal 28, rr

  it "decode renvoie nil sur message tronqué", ->
    assert.is_nil (codec.decode "short")
