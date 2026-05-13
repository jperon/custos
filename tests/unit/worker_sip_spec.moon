describe "worker_sip helpers", ->
  worker_sip = require "worker_sip"

  describe "classify_direction", ->
    it "returns not-sip when neither side uses port 5060", ->
      outbound, inbound, is_sip = worker_sip.classify_direction 4242, 4243, "10.35.1.2", "10.35.1.3"
      assert.is_false outbound
      assert.is_false inbound
      assert.is_false is_sip

    it "classifies outbound request to 5060", ->
      outbound, inbound, is_sip = worker_sip.classify_direction 5072, 5060, "10.35.3.6", "83.136.161.35"
      assert.is_true outbound
      assert.is_false inbound
      assert.is_true is_sip

    it "classifies inbound when destination is a known phone even with random source port", ->
      worker_sip.remember_phone_ip "10.35.3.6", "48:25:67:f7:96:52"
      outbound, inbound, is_sip = worker_sip.classify_direction 49832, 5060, "83.136.161.35", "10.35.3.6"
      assert.is_false outbound
      assert.is_true inbound
      assert.is_true is_sip

  describe "resolve_outbound_mac", ->
    it "prefers cached phone MAC over packet MAC", ->
      worker_sip.remember_phone_ip "10.35.3.6", "48:25:67:f7:96:52"
      mac = worker_sip.resolve_outbound_mac "10.35.3.6", "58:d6:1f:57:4f:94"
      assert.are.equal "48:25:67:f7:96:52", mac

    it "falls back to packet MAC when cache is empty", ->
      mac = worker_sip.resolve_outbound_mac "10.35.3.250", "48:25:67:f7:96:52"
      assert.are.equal "48:25:67:f7:96:52", mac

    it "does not use packet MAC fallback for non-lan source IP", ->
      mac = worker_sip.resolve_outbound_mac "83.136.164.102", "58:d6:1f:57:4f:94"
      assert.is_nil mac
