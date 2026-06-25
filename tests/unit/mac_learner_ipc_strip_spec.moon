-- tests/unit/mac_learner_ipc_strip_spec.moon
-- Test du parseur pur de la réponse "strip:<name>" du MAC learner.
-- Le chemin socket complet (identique à get_vlan) est couvert e2e (Task 8).

describe "mac_learner_ipc.parse_strip_resp", ->
  it "parse un rr_code numérique", ->
    ipc = require "mac_learner_ipc"
    assert.are.equal 28, ipc.parse_strip_resp "28\n"

  it "renvoie nil sur 'unknown'", ->
    ipc = require "mac_learner_ipc"
    assert.is_nil ipc.parse_strip_resp "unknown\n"

  it "renvoie nil sur chaîne vide", ->
    ipc = require "mac_learner_ipc"
    assert.is_nil ipc.parse_strip_resp ""
