-- tests/unit/worker_questions_metrics_spec.moon
-- Integration tests for metrics recording in worker_questions rule evaluation.

{
  :init
  :record_verdict
  :record_cache
  :record_ttl
  :get_rule_metrics
  :clear
} = require "metrics"

describe "worker_questions metrics integration", ->

  before_each ->
    clear!

  describe "verdict recording", ->

    it "records allow verdict when rule decision allows", ->
      -- Simulate: rule evaluation returns allowed=true
      record_verdict "allow_rule", "allow"
      m = get_rule_metrics "allow_rule"
      assert.equals 1, m.verdicts.allow
      assert.equals 0, m.verdicts.refuse
      assert.equals 0, m.verdicts.dnsonly

    it "records refuse verdict when rule decision blocks", ->
      -- Simulate: rule evaluation returns allowed=false
      record_verdict "block_rule", "refuse"
      m = get_rule_metrics "block_rule"
      assert.equals 0, m.verdicts.allow
      assert.equals 1, m.verdicts.refuse
      assert.equals 0, m.verdicts.dnsonly

    it "records dnsonly verdict for dnsonly responses", ->
      -- Simulate: rule evaluation returns allowed='dnsonly'
      record_verdict "dnsonly_rule", "dnsonly"
      m = get_rule_metrics "dnsonly_rule"
      assert.equals 0, m.verdicts.allow
      assert.equals 0, m.verdicts.refuse
      assert.equals 1, m.verdicts.dnsonly

    it "counts multiple verdicts for same rule", ->
      for i = 1, 5
        record_verdict "frequent_rule", "allow"
      for i = 1, 3
        record_verdict "frequent_rule", "refuse"
      for i = 1, 1
        record_verdict "frequent_rule", "dnsonly"

      m = get_rule_metrics "frequent_rule"
      assert.equals 5, m.verdicts.allow
      assert.equals 3, m.verdicts.refuse
      assert.equals 1, m.verdicts.dnsonly

    it "tracks separate verdicts for different rules", ->
      -- Simulate multiple rules being evaluated
      record_verdict "rule_a", "allow"
      record_verdict "rule_a", "allow"
      record_verdict "rule_b", "refuse"
      record_verdict "rule_b", "refuse"
      record_verdict "rule_c", "dnsonly"

      a = get_rule_metrics "rule_a"
      b = get_rule_metrics "rule_b"
      c = get_rule_metrics "rule_c"

      assert.equals 2, a.verdicts.allow
      assert.equals 2, b.verdicts.refuse
      assert.equals 1, c.verdicts.dnsonly

  describe "cache metrics integration", ->

    it "records DNS cache hits and misses", ->
      -- Simulate DNS response caching
      for i = 1, 8
        record_cache "dns_cache_rule", true
      for i = 1, 2
        record_cache "dns_cache_rule", false

      m = get_rule_metrics "dns_cache_rule"
      assert.equals 8, m.cache.hits
      assert.equals 2, m.cache.misses
      assert.equals 80, m.cache.hit_rate

    it "calculates cache hit rate correctly", ->
      -- Perfect cache
      for i = 1, 100
        record_cache "perfect_cache", true
      m = get_rule_metrics "perfect_cache"
      assert.equals 100, m.cache.hit_rate

      -- Half cache
      clear!
      for i = 1, 5
        record_cache "half_cache", true
      for i = 1, 5
        record_cache "half_cache", false
      m = get_rule_metrics "half_cache"
      assert.equals 50, m.cache.hit_rate

      -- No cache hits
      clear!
      for i = 1, 10
        record_cache "no_cache", false
      m = get_rule_metrics "no_cache"
      assert.equals 0, m.cache.hit_rate

    it "tracks cache independently per rule", ->
      for i = 1, 10
        record_cache "rule_x", true
      for i = 1, 5
        record_cache "rule_y", false

      x = get_rule_metrics "rule_x"
      y = get_rule_metrics "rule_y"

      assert.equals 10, x.cache.hits
      assert.equals 0, x.cache.misses
      assert.equals 0, y.cache.hits
      assert.equals 5, y.cache.misses

  describe "TTL metrics integration", ->

    it "records TTL values from DNS responses", ->
      -- Simulate TTL values from different responses
      record_ttl "ttl_rule", 60    -- 1 minute
      record_ttl "ttl_rule", 3600  -- 1 hour
      record_ttl "ttl_rule", 86400 -- 1 day

      m = get_rule_metrics "ttl_rule"
      assert.equals 60, m.ttl.min
      assert.equals 86400, m.ttl.max
      assert.equals 30020, m.ttl.avg  -- (60 + 3600 + 86400) / 3 = 30020

    it "handles realistic TTL distribution", ->
      ttls = { 300, 300, 600, 300, 3600, 60, 300, 900, 60, 86400 }
      for ttl in *ttls
        record_ttl "realistic_ttl", ttl

      m = get_rule_metrics "realistic_ttl"
      assert.equals 60, m.ttl.min
      assert.equals 86400, m.ttl.max
      -- Average of [300, 300, 600, 300, 3600, 60, 300, 900, 60, 86400] = 9282
      assert.equals 9282, m.ttl.avg

    it "keeps only last 100 TTL samples", ->
      for i = 1, 150
        record_ttl "high_volume_rule", i * 10

      m = get_rule_metrics "high_volume_rule"
      -- Should have kept samples 51-150
      assert.equals 510, m.ttl.min  -- 51 * 10
      assert.equals 1500, m.ttl.max  -- 150 * 10

  describe "combined metrics scenarios", ->

    it "tracks complete lifecycle of a rule", ->
      -- Simulate repeated DNS requests for a rule
      for req = 1, 10
        if req <= 7
          record_verdict "facebook_rule", "allow"
        else
          record_verdict "facebook_rule", "refuse"

      -- Track cache behavior
      for req = 1, 8
        record_cache "facebook_rule", true
      for req = 1, 2
        record_cache "facebook_rule", false

      -- Track TTL values
      record_ttl "facebook_rule", 300  -- 5 min
      record_ttl "facebook_rule", 300
      record_ttl "facebook_rule", 3600  -- 1 hour

      m = get_rule_metrics "facebook_rule"
      assert.equals 7, m.verdicts.allow
      assert.equals 3, m.verdicts.refuse
      assert.equals 8, m.cache.hits
      assert.equals 2, m.cache.misses
      assert.equals 80, m.cache.hit_rate
      assert.equals 300, m.ttl.min
      assert.equals 3600, m.ttl.max

    it "separates metrics for different rules in same session", ->
      -- Rule 1: allow_https - mostly allowed
      for i = 1, 8
        record_verdict "allow_https", "allow"
      for i = 1, 1
        record_verdict "allow_https", "refuse"

      -- Rule 2: block_ads - mostly refused
      for i = 1, 2
        record_verdict "block_ads", "allow"
      for i = 1, 8
        record_verdict "block_ads", "refuse"

      -- Rule 3: dnsonly_china - all dnsonly
      for i = 1, 5
        record_verdict "dnsonly_china", "dnsonly"

      r1 = get_rule_metrics "allow_https"
      r2 = get_rule_metrics "block_ads"
      r3 = get_rule_metrics "dnsonly_china"

      assert.equals 8, r1.verdicts.allow
      assert.equals 1, r1.verdicts.refuse
      assert.equals 0, r1.verdicts.dnsonly

      assert.equals 2, r2.verdicts.allow
      assert.equals 8, r2.verdicts.refuse
      assert.equals 0, r2.verdicts.dnsonly

      assert.equals 0, r3.verdicts.allow
      assert.equals 0, r3.verdicts.refuse
      assert.equals 5, r3.verdicts.dnsonly

    it "handles mixed metrics across rules", ->
      -- Multiple rules with different metrics patterns
      rules_data = {
        rule_1: { verdicts: { allow: 100, refuse: 5 }, cache_hits: 80, cache_misses: 25, ttls: { 60, 300, 3600 } }
        rule_2: { verdicts: { allow: 50, refuse: 50 }, cache_hits: 40, cache_misses: 60, ttls: { 120, 7200 } }
        rule_3: { verdicts: { allow: 200, refuse: 0 }, cache_hits: 150, cache_misses: 50, ttls: { 1800, 86400 } }
      }

      -- Record rule_1 metrics
      for i = 1, 100
        record_verdict "rule_1", "allow"
      for i = 1, 5
        record_verdict "rule_1", "refuse"
      for i = 1, 80
        record_cache "rule_1", true
      for i = 1, 25
        record_cache "rule_1", false
      record_ttl "rule_1", 60
      record_ttl "rule_1", 300
      record_ttl "rule_1", 3600

      -- Record rule_2 metrics
      for i = 1, 50
        record_verdict "rule_2", "allow"
      for i = 1, 50
        record_verdict "rule_2", "refuse"
      for i = 1, 40
        record_cache "rule_2", true
      for i = 1, 60
        record_cache "rule_2", false
      record_ttl "rule_2", 120
      record_ttl "rule_2", 7200

      -- Record rule_3 metrics
      for i = 1, 200
        record_verdict "rule_3", "allow"
      for i = 1, 150
        record_cache "rule_3", true
      for i = 1, 50
        record_cache "rule_3", false
      record_ttl "rule_3", 1800
      record_ttl "rule_3", 86400

      -- Verify all rules tracked correctly
      m1 = get_rule_metrics "rule_1"
      m2 = get_rule_metrics "rule_2"
      m3 = get_rule_metrics "rule_3"

      -- Rule 1
      assert.equals 100, m1.verdicts.allow
      assert.equals 5, m1.verdicts.refuse
      assert.equals 80, m1.cache.hits
      assert.equals 25, m1.cache.misses
      assert.equals 60, m1.ttl.min
      assert.equals 3600, m1.ttl.max

      -- Rule 2
      assert.equals 50, m2.verdicts.allow
      assert.equals 50, m2.verdicts.refuse
      assert.equals 40, m2.cache.hits
      assert.equals 60, m2.cache.misses
      assert.equals 120, m2.ttl.min
      assert.equals 7200, m2.ttl.max

      -- Rule 3
      assert.equals 200, m3.verdicts.allow
      assert.equals 0, m3.verdicts.refuse
      assert.equals 150, m3.cache.hits
      assert.equals 50, m3.cache.misses
      assert.equals 1800, m3.ttl.min
      assert.equals 86400, m3.ttl.max

  describe "metrics with disabled state", ->

    it "does not record metrics when disabled", ->
      init { enabled: false }
      record_verdict "disabled_rule", "allow"
      m = get_rule_metrics "disabled_rule"
      assert.is_nil m

    it "allows re-enabling metrics", ->
      init { enabled: false }
      record_verdict "disabled", "allow"
      init { enabled: true }
      record_verdict "enabled", "allow"
      assert.is_nil get_rule_metrics "disabled"
      assert.is_not_nil get_rule_metrics "enabled"
