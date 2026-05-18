-- tests/test_phase_c1_nft_queue.moon
-- Unit tests for Phase C1 per-rule set naming and timeout composition

describe "nft_queue per-rule sets (Phase C1)", ->
  local nft_queue, get_set_name, cmd_for, sanitize_rule_id

  before_each ->
    nft_queue = require "nft_queue"
    get_set_name = nft_queue.get_set_name
    cmd_for = nft_queue.cmd_for
    sanitize_rule_id = nft_queue.sanitize_rule_id

  describe "sanitize_rule_id", ->
    it "returns empty string for nil", ->
      assert.equal "", sanitize_rule_id(nil)
    
    it "returns empty string for empty string", ->
      assert.equal "", sanitize_rule_id("")
    
    it "returns rule_id as-is for valid hex", ->
      assert.equal "61626364", sanitize_rule_id("61626364")
    
    it "truncates to 126 chars for oversized rule_id", ->
      long_id = string.rep("a", 150)
      result = sanitize_rule_id(long_id)
      assert.equal 126, #result
    
    it "converts non-string to string", ->
      result = sanitize_rule_id(12345)
      assert.equal "12345", result

  describe "get_set_name", ->
    it "returns nil for empty rule_id and ip4 (per-rule required)", ->
      result = get_set_name("ip4", "")
      assert.is_nil result

    it "returns nil for empty rule_id and ip6 (per-rule required)", ->
      result = get_set_name("ip6", "")
      assert.is_nil result

    it "returns nil for empty rule_id and mac4 (per-rule required)", ->
      result = get_set_name("mac4", "")
      assert.is_nil result

    it "returns nil for empty rule_id and mac6 (per-rule required)", ->
      result = get_set_name("mac6", "")
      assert.is_nil result

    it "returns per-rule set rule_test_ip4 for rule_id and ip4", ->
      result = get_set_name("ip4", "test")
      assert.equal "rule_test_ip4", result
    
    it "returns per-rule set rule_test_ip6 for rule_id and ip6", ->
      result = get_set_name("ip6", "test")
      assert.equal "rule_test_ip6", result
    
    it "returns per-rule set rule_test_mac4 for rule_id and mac4", ->
      result = get_set_name("mac4", "test")
      assert.equal "rule_test_mac4", result
    
    it "returns per-rule set rule_test_mac6 for rule_id and mac6", ->
      result = get_set_name("mac6", "test")
      assert.equal "rule_test_mac6", result
    
    it "returns nil for nil kind with rule_id", ->
      result = get_set_name("invalid", "test")
      assert.is_nil result
    
    it "handles hex-encoded rule_id", ->
      result = get_set_name("ip4", "61626364")
      assert.equal "rule_61626364_ip4", result

  describe "cmd_for with rule_id", ->
    it "generates IPv4 add element command with rule_id", ->
      cmd = cmd_for("ip4", "192.168.1.100", "10.0.0.1", "test", "60s")
      assert.match "add element bridge dns%-filter%-bridge rule_test_ip4", cmd
      assert.match "192%.168%.1%.100", cmd
      assert.match "10%.0%.0%.1", cmd
      assert.match "timeout 60s", cmd
    
    it "generates IPv6 add element command with rule_id", ->
      cmd = cmd_for("ip6", "2001:db8::1", "2001:db8::2", "test", "120s")
      assert.match "add element bridge dns%-filter%-bridge rule_test_ip6", cmd
      assert.match "2001:db8::1", cmd
      assert.match "2001:db8::2", cmd
      assert.match "timeout 120s", cmd
    
    it "generates MAC4 add element command with rule_id", ->
      cmd = cmd_for("mac4", "aa:bb:cc:dd:ee:ff", "10.0.0.1", "test", "180s")
      assert.match "add element bridge dns%-filter%-bridge rule_test_mac4", cmd
      assert.match "aa:bb:cc:dd:ee:ff", cmd
      assert.match "timeout 180s", cmd
    
    it "generates MAC6 add element command with rule_id", ->
      cmd = cmd_for("mac6", "aa:bb:cc:dd:ee:ff", "2001:db8::1", "test", "300s")
      assert.match "add element bridge dns%-filter%-bridge rule_test_mac6", cmd
      assert.match "aa:bb:cc:dd:ee:ff", cmd
      assert.match "timeout 300s", cmd
    
    it "falls back to global sets for empty rule_id", ->
      cmd = cmd_for("ip4", "192.168.1.100", "10.0.0.1", "", "60s")
      assert.match "add element bridge dns%-filter%-bridge ip4_allowed", cmd
    
    it "returns nil for invalid kind", ->
      cmd = cmd_for("invalid", "192.168.1.100", "10.0.0.1", "test", "60s")
      assert.is_nil cmd
    
    it "sanitizes timeout to default on invalid", ->
      cmd = cmd_for("ip4", "192.168.1.100", "10.0.0.1", "test", "invalid_timeout")
      assert.is_not_nil cmd
      assert.match "timeout 2m", cmd  -- Default timeout
    
    it "handles long rule_id", ->
      long_id = string.rep("a", 100)
      cmd = cmd_for("ip4", "192.168.1.100", "10.0.0.1", long_id, "60s")
      assert.is_not_nil cmd
      assert.match "rule_" .. string.rep("a", 100) .. "_ip4", cmd

  describe "per-rule set naming consistency", ->
    it "same rule_id and kind produce same set name", ->
      name1 = get_set_name("ip4", "rule123")
      name2 = get_set_name("ip4", "rule123")
      assert.equal name1, name2
    
    it "different kinds produce different set names for same rule_id", ->
      name_ip4 = get_set_name("ip4", "rule123")
      name_ip6 = get_set_name("ip6", "rule123")
      assert.not_equal name_ip4, name_ip6
      assert.equal "rule_rule123_ip4", name_ip4
      assert.equal "rule_rule123_ip6", name_ip6
    
    it "different rule_ids produce different set names for same kind", ->
      name1 = get_set_name("ip4", "rule1")
      name2 = get_set_name("ip4", "rule2")
      assert.not_equal name1, name2
      assert.equal "rule_rule1_ip4", name1
      assert.equal "rule_rule2_ip4", name2

  describe "timeout composition (from worker_responses)", ->
    local worker_responses
    
    before_each ->
      worker_responses = require "worker_responses"
    
    it "rr_timeout returns TTL + grace clamped to min/max", ->
      -- Test default config: grace=600, min=60, max=2592000
      timeout_str, timeout_num = worker_responses.rr_timeout(60)
      assert.equal "660s", timeout_str
      assert.equal 660, timeout_num
    
    it "rr_timeout returns min for very low TTL", ->
      timeout_str, timeout_num = worker_responses.rr_timeout(1)
      assert.equal "601s", timeout_str  -- 1 + 600 = 601, but clamped to min=60+1=61
    
    it "rr_timeout clamps to min boundary", ->
      -- TTL=0 + grace=600 = 600, but min=60, max=2592000
      -- Actually: max(1, floor(0)) + 600 = 0 + 600 = 600
      -- clamp(600, 60, 2592000) = 600
      timeout_str, _ = worker_responses.rr_timeout(0)
      assert.equal "600s", timeout_str
    
    it "rr_timeout clamps to max boundary", ->
      -- TTL=3000000 + grace=600 = 3000600
      -- clamp(3000600, 60, 2592000) = 2592000
      timeout_str, _ = worker_responses.rr_timeout(3000000)
      assert.equal "2592000s", timeout_str

