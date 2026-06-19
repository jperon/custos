-- tests/unit/mac_learner_vlan_spec.moon
-- Apprentissage IP→VLAN du mac_learner (alimenté par worker_doh_vlan) :
-- process_vlan_learn + vlan_lookup, untagged explicite et écrasement anti-stale.

ml = require "mac_learner"

-- Construit un message vlan_learn : ip16 (IPv4 paddée) + vlan BE = 18 octets.
msg_for = (ipv4, vlan) ->
  a, b, c, d = ipv4\match "(%d+)%.(%d+)%.(%d+)%.(%d+)"
  ip16 = string.char(tonumber(a), tonumber(b), tonumber(c), tonumber(d)) .. string.rep("\0", 12)
  ip16 .. string.char(math.floor(vlan / 256) % 256, vlan % 256)

describe "mac_learner VLAN", ->
  it "apprend un VLAN tagué et le retrouve", ->
    ml.process_vlan_learn msg_for "10.0.0.5", 100
    assert.equals 100, ml.vlan_lookup "10.0.0.5"

  it "untagged (0) est mémorisé tel quel (distinct d'inconnu)", ->
    ml.process_vlan_learn msg_for "10.0.0.6", 0
    assert.equals 0, ml.vlan_lookup "10.0.0.6"

  it "IP jamais vue → nil (inconnu)", ->
    assert.is_nil ml.vlan_lookup "10.0.0.250"

  it "transition tagué→untagged écrase l'entrée (anti-spoofing)", ->
    ml.process_vlan_learn msg_for "10.0.0.7", 100
    assert.equals 100, ml.vlan_lookup "10.0.0.7"
    ml.process_vlan_learn msg_for "10.0.0.7", 0   -- même IP, untagged
    assert.equals 0, ml.vlan_lookup "10.0.0.7"    -- plus 100

  it "message trop court (< 18) ignoré", ->
    ml.process_vlan_learn string.rep "\0", 17
    -- pas de plantage ; l'IP 0.0.0.0 ne doit pas être renseignée
    assert.is_nil ml.vlan_lookup "0.0.0.0"
