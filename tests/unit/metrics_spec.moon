-- tests/unit/metrics_spec.moon
-- Tests for per-rule metrics collection and aggregation.

{
  :init
  :record_verdict
  :record_cache
  :record_ttl
  :flush_metrics
  :get_metrics_json
  :get_snapshot
  :get_rule_metrics
  :clear
  :_get_state
  :_get_hit_rate
  :_get_ttl_stats
} = require "metrics"

describe "metrics", ->

  before_each ->
    clear!

  describe "record_verdict", ->

    it "initializes counter for new rule", ->
      record_verdict "rule1", "allow"
      state = _get_state!
      assert.is_not_nil state["rule1"]
      assert.equals 1, state["rule1"].allow_count

    it "increments allow counter", ->
      record_verdict "rule1", "allow"
      record_verdict "rule1", "allow"
      record_verdict "rule1", "allow"
      state = _get_state!
      assert.equals 3, state["rule1"].allow_count

    it "increments refuse counter", ->
      record_verdict "rule1", "refuse"
      record_verdict "rule1", "refuse"
      state = _get_state!
      assert.equals 2, state["rule1"].refuse_count

    it "increments dnsonly counter", ->
      record_verdict "rule1", "dnsonly"
      record_verdict "rule1", "dnsonly"
      record_verdict "rule1", "dnsonly"
      state = _get_state!
      assert.equals 3, state["rule1"].dnsonly_count

    it "handles multiple rules", ->
      record_verdict "rule1", "allow"
      record_verdict "rule2", "refuse"
      record_verdict "rule1", "allow"
      record_verdict "rule2", "dnsonly"
      state = _get_state!
      assert.equals 2, state["rule1"].allow_count
      assert.equals 1, state["rule2"].refuse_count
      assert.equals 1, state["rule2"].dnsonly_count

    it "ignores nil rule_id", ->
      record_verdict nil, "allow"
      state = _get_state!
      assert.equals 0, #state

    it "ignores nil verdict", ->
      record_verdict "rule1", nil
      state = _get_state!
      assert.equals 0, #state

    it "ignores invalid verdict", ->
      record_verdict "rule1", "invalid"
      state = _get_state!
      assert.equals 0, state["rule1"].allow_count + state["rule1"].refuse_count + state["rule1"].dnsonly_count

  describe "record_cache", ->

    it "records cache hit", ->
      record_cache "rule1", true
      state = _get_state!
      assert.equals 1, state["rule1"].cache_hits
      assert.equals 0, state["rule1"].cache_misses

    it "records cache miss", ->
      record_cache "rule1", false
      state = _get_state!
      assert.equals 0, state["rule1"].cache_hits
      assert.equals 1, state["rule1"].cache_misses

    it "counts multiple hits and misses", ->
      record_cache "rule1", true
      record_cache "rule1", true
      record_cache "rule1", false
      record_cache "rule1", false
      record_cache "rule1", false
      state = _get_state!
      assert.equals 2, state["rule1"].cache_hits
      assert.equals 3, state["rule1"].cache_misses

    it "handles multiple rules", ->
      record_cache "rule1", true
      record_cache "rule2", false
      state = _get_state!
      assert.equals 1, state["rule1"].cache_hits
      assert.equals 1, state["rule2"].cache_misses

    it "ignores nil rule_id", ->
      record_cache nil, true
      state = _get_state!
      assert.equals 0, #state

  describe "record_ttl", ->

    it "records single TTL sample", ->
      record_ttl "rule1", 3600
      state = _get_state!
      assert.equals 1, #state["rule1"].ttl_samples
      assert.equals 3600, state["rule1"].ttl_samples[1]

    it "records multiple TTL samples", ->
      record_ttl "rule1", 3600
      record_ttl "rule1", 7200
      record_ttl "rule1", 1800
      state = _get_state!
      assert.equals 3, #state["rule1"].ttl_samples
      assert.equals 3600, state["rule1"].ttl_samples[1]
      assert.equals 7200, state["rule1"].ttl_samples[2]
      assert.equals 1800, state["rule1"].ttl_samples[3]

    it "keeps only last 100 samples per rule", ->
      for i = 1, 150
        record_ttl "rule1", i * 100
      state = _get_state!
      assert.equals 100, #state["rule1"].ttl_samples
      assert.equals 51 * 100, state["rule1"].ttl_samples[1]  -- Samples 1-50 evicted

    it "ignores nil rule_id", ->
      record_ttl nil, 3600
      state = _get_state!
      assert.equals 0, #state

    it "ignores non-numeric ttl", ->
      record_ttl "rule1", "3600"
      state = _get_state!
      assert.is_nil state["rule1"]

  describe "cache hit rate", ->

    it "calculates hit rate percentage", ->
      record_cache "rule1", true
      record_cache "rule1", true
      record_cache "rule1", true
      record_cache "rule1", false
      record_cache "rule1", false
      rate = _get_hit_rate "rule1"
      assert.equals 60, rate

    it "returns 0 with no cache access", ->
      record_verdict "rule1", "allow"
      rate = _get_hit_rate "rule1"
      assert.equals 0, rate

    it "handles all hits", ->
      record_cache "rule1", true
      record_cache "rule1", true
      record_cache "rule1", true
      rate = _get_hit_rate "rule1"
      assert.equals 100, rate

    it "handles all misses", ->
      record_cache "rule1", false
      record_cache "rule1", false
      rate = _get_hit_rate "rule1"
      assert.equals 0, rate

    it "returns 0 for undefined rule", ->
      rate = _get_hit_rate "undefined_rule"
      assert.equals 0, rate

  describe "TTL statistics", ->

    it "calculates min, max, avg for samples", ->
      record_ttl "rule1", 1000
      record_ttl "rule1", 2000
      record_ttl "rule1", 3000
      stats = _get_ttl_stats "rule1"
      assert.equals 1000, stats.min
      assert.equals 3000, stats.max
      assert.equals 2000, stats.avg

    it "handles single sample", ->
      record_ttl "rule1", 5000
      stats = _get_ttl_stats "rule1"
      assert.equals 5000, stats.min
      assert.equals 5000, stats.max
      assert.equals 5000, stats.avg

    it "returns zeros for undefined rule", ->
      stats = _get_ttl_stats "undefined_rule"
      assert.equals 0, stats.min
      assert.equals 0, stats.max
      assert.equals 0, stats.avg

    it "returns zeros for rule with no TTL samples", ->
      record_verdict "rule1", "allow"
      stats = _get_ttl_stats "rule1"
      assert.equals 0, stats.min
      assert.equals 0, stats.max
      assert.equals 0, stats.avg

  describe "get_metrics_json", ->

    it "exports metrics as JSON-compatible table", ->
      record_verdict "rule1", "allow"
      record_verdict "rule1", "allow"
      record_verdict "rule1", "refuse"
      record_cache "rule1", true
      record_cache "rule1", false
      record_ttl "rule1", 3600
      record_ttl "rule1", 7200

      json = get_metrics_json!
      assert.is_not_nil json.timestamp
      assert.equals 1, #json.rules
      rule = json.rules[1]
      assert.equals "rule1", rule.rule_id
      assert.equals 2, rule.verdicts.allow
      assert.equals 1, rule.verdicts.refuse
      assert.equals 0, rule.verdicts.dnsonly
      assert.equals 1, rule.cache.hits
      assert.equals 1, rule.cache.misses
      assert.equals 50, rule.cache.hit_rate
      assert.equals 3600, rule.ttl.min
      assert.equals 7200, rule.ttl.max
      assert.equals 5400, rule.ttl.avg

    it "includes all rules in export", ->
      record_verdict "rule1", "allow"
      record_verdict "rule2", "refuse"
      record_verdict "rule3", "dnsonly"

      json = get_metrics_json!
      assert.equals 3, #json.rules
      rule_ids = {}
      for r in *json.rules
        rule_ids[r.rule_id] = true
      assert.is_true rule_ids["rule1"]
      assert.is_true rule_ids["rule2"]
      assert.is_true rule_ids["rule3"]

    it "exports empty metrics for no data", ->
      json = get_metrics_json!
      assert.equals 0, #json.rules

  describe "get_snapshot", ->

    it "returns same format as get_metrics_json", ->
      record_verdict "rule1", "allow"
      snap = get_snapshot!
      json = get_metrics_json!
      assert.equals json.timestamp, snap.timestamp
      assert.equals #json.rules, #snap.rules

    it "does not modify state after snapshot", ->
      record_verdict "rule1", "allow"
      snap1 = get_snapshot!
      record_verdict "rule1", "allow"
      snap2 = get_snapshot!
      assert.equals 1, snap1.rules[1].verdicts.allow
      assert.equals 2, snap2.rules[1].verdicts.allow

  describe "get_rule_metrics", ->

    it "returns metrics for single rule", ->
      record_verdict "rule1", "allow"
      record_cache "rule1", true
      record_ttl "rule1", 3600

      m = get_rule_metrics "rule1"
      assert.is_not_nil m
      assert.equals "rule1", m.rule_id
      assert.equals 1, m.verdicts.allow

    it "returns nil for undefined rule", ->
      m = get_rule_metrics "undefined"
      assert.is_nil m

    it "returns nil for nil rule_id", ->
      m = get_rule_metrics nil
      assert.is_nil m

  describe "flush_metrics", ->

    it "returns snapshot before reset", ->
      record_verdict "rule1", "allow"
      record_verdict "rule1", "allow"

      snapshot = flush_metrics!
      assert.equals 1, #snapshot.rules
      assert.equals 2, snapshot.rules[1].verdicts.allow

    it "clears metrics after flush", ->
      record_verdict "rule1", "allow"
      flush_metrics!

      json = get_metrics_json!
      assert.equals 0, #json.rules

    it "allows new metrics after flush", ->
      record_verdict "rule1", "allow"
      flush_metrics!
      record_verdict "rule2", "refuse"

      json = get_metrics_json!
      assert.equals 1, #json.rules
      assert.equals "rule2", json.rules[1].rule_id

  describe "memory bounded", ->

    it "evicts LRU rule when exceeding MAX_RULES", ->
      -- Set max to 5 for testing
      init { max_rules: 5, enabled: true }

      for i = 1, 6
        record_verdict "rule#{i}", "allow"

      json = get_metrics_json!
      -- Should have 5 rules, first one evicted
      assert.equals 5, #json.rules
      -- Check that rule1 is not present (LRU evicted)
      found = false
      for r in *json.rules
        found = true if r.rule_id == "rule1"
      assert.is_false found

    it "keeps most recent rules after eviction", ->
      init { max_rules: 3, enabled: true }

      record_verdict "rule1", "allow"
      record_verdict "rule2", "allow"
      record_verdict "rule3", "allow"
      record_verdict "rule4", "allow"  -- Evicts rule1

      json = get_metrics_json!
      rule_ids = {}
      for r in *json.rules
        rule_ids[r.rule_id] = true
      assert.is_nil rule_ids["rule1"]
      assert.is_true rule_ids["rule2"]
      assert.is_true rule_ids["rule3"]
      assert.is_true rule_ids["rule4"]

  describe "integration", ->

    it "tracks combined metrics for complex scenario", ->
      -- Simulate DNS requests
      for i = 1, 10
        if i <= 7
          record_verdict "secure_rule", "allow"
        else
          record_verdict "secure_rule", "refuse"

      for i = 1, 8
        record_cache "secure_rule", true
      for i = 1, 2
        record_cache "secure_rule", false

      for i = 1, 5
        record_ttl "secure_rule", 300 + (i * 60)

      m = get_rule_metrics "secure_rule"
      assert.equals 7, m.verdicts.allow
      assert.equals 3, m.verdicts.refuse
      assert.equals 0, m.verdicts.dnsonly
      assert.equals 8, m.cache.hits
      assert.equals 2, m.cache.misses
      assert.equals 80, m.cache.hit_rate
      assert.equals 360, m.ttl.min
      assert.equals 600, m.ttl.max

    it "handles zero metrics correctly", ->
      record_verdict "empty_rule", "allow"
      record_verdict "empty_rule", "allow"
      -- No cache or TTL records

      m = get_rule_metrics "empty_rule"
      assert.equals 2, m.verdicts.allow
      assert.equals 0, m.cache.hits
      assert.equals 0, m.cache.misses
      assert.equals 0, m.cache.hit_rate
      assert.equals 0, m.ttl.min
      assert.equals 0, m.ttl.max
      assert.equals 0, m.ttl.avg

    it "maintains separate rule metrics", ->
      record_verdict "rule_a", "allow"
      record_verdict "rule_a", "allow"
      record_verdict "rule_b", "refuse"
      record_verdict "rule_b", "refuse"

      a = get_rule_metrics "rule_a"
      b = get_rule_metrics "rule_b"
      assert.equals 2, a.verdicts.allow
      assert.equals 0, a.verdicts.refuse
      assert.equals 0, b.verdicts.allow
      assert.equals 2, b.verdicts.refuse
