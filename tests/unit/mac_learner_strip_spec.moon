-- tests/unit/mac_learner_strip_spec.moon
-- Table de cibles de strip CNAME (mac_learner) : process_strip_learn + strip_lookup,
-- alimentée par strip_codec (Tâche 1), en miroir de mac_learner_vlan_spec.

ml = require "mac_learner"
codec = require "strip_codec"

describe "mac_learner strip_table", ->
  it "apprend une cible et la retrouve par nom (insensible à la casse)", ->
    ml.process_strip_learn codec.encode("atm.outlook.mira.tm.svc.cloud.microsoft", 28)
    assert.are.equal 28, ml.strip_lookup "ATM.outlook.mira.tm.svc.cloud.microsoft."

  it "renvoie nil pour un nom jamais appris", ->
    assert.is_nil ml.strip_lookup "example.org"

  it "expire après le TTL", ->
    real = os.time
    ml.process_strip_learn codec.encode("ephemere.example", 28)
    os.time = -> real! + 10000
    assert.is_nil ml.strip_lookup "ephemere.example"
    os.time = real
