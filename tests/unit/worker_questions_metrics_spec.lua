local init, record_verdict, record_cache, record_ttl, get_rule_metrics, clear
do
  local _obj_0 = require("metrics")
  init, record_verdict, record_cache, record_ttl, get_rule_metrics, clear = _obj_0.init, _obj_0.record_verdict, _obj_0.record_cache, _obj_0.record_ttl, _obj_0.get_rule_metrics, _obj_0.clear
end
return describe("worker_questions metrics integration", function()
  before_each(function()
    return clear()
  end)
  describe("verdict recording", function()
    it("records allow verdict when rule decision allows", function()
      record_verdict("allow_rule", "allow")
      local m = get_rule_metrics("allow_rule")
      assert.equals(1, m.verdicts.allow)
      assert.equals(0, m.verdicts.refuse)
      return assert.equals(0, m.verdicts.dnsonly)
    end)
    it("records refuse verdict when rule decision blocks", function()
      record_verdict("block_rule", "refuse")
      local m = get_rule_metrics("block_rule")
      assert.equals(0, m.verdicts.allow)
      assert.equals(1, m.verdicts.refuse)
      return assert.equals(0, m.verdicts.dnsonly)
    end)
    it("records dnsonly verdict for dnsonly responses", function()
      record_verdict("dnsonly_rule", "dnsonly")
      local m = get_rule_metrics("dnsonly_rule")
      assert.equals(0, m.verdicts.allow)
      assert.equals(0, m.verdicts.refuse)
      return assert.equals(1, m.verdicts.dnsonly)
    end)
    it("counts multiple verdicts for same rule", function()
      for i = 1, 5 do
        record_verdict("frequent_rule", "allow")
      end
      for i = 1, 3 do
        record_verdict("frequent_rule", "refuse")
      end
      for i = 1, 1 do
        record_verdict("frequent_rule", "dnsonly")
      end
      local m = get_rule_metrics("frequent_rule")
      assert.equals(5, m.verdicts.allow)
      assert.equals(3, m.verdicts.refuse)
      return assert.equals(1, m.verdicts.dnsonly)
    end)
    return it("tracks separate verdicts for different rules", function()
      record_verdict("rule_a", "allow")
      record_verdict("rule_a", "allow")
      record_verdict("rule_b", "refuse")
      record_verdict("rule_b", "refuse")
      record_verdict("rule_c", "dnsonly")
      local a = get_rule_metrics("rule_a")
      local b = get_rule_metrics("rule_b")
      local c = get_rule_metrics("rule_c")
      assert.equals(2, a.verdicts.allow)
      assert.equals(2, b.verdicts.refuse)
      return assert.equals(1, c.verdicts.dnsonly)
    end)
  end)
  describe("cache metrics integration", function()
    it("records DNS cache hits and misses", function()
      for i = 1, 8 do
        record_cache("dns_cache_rule", true)
      end
      for i = 1, 2 do
        record_cache("dns_cache_rule", false)
      end
      local m = get_rule_metrics("dns_cache_rule")
      assert.equals(8, m.cache.hits)
      assert.equals(2, m.cache.misses)
      return assert.equals(80, m.cache.hit_rate)
    end)
    it("calculates cache hit rate correctly", function()
      for i = 1, 100 do
        record_cache("perfect_cache", true)
      end
      local m = get_rule_metrics("perfect_cache")
      assert.equals(100, m.cache.hit_rate)
      clear()
      for i = 1, 5 do
        record_cache("half_cache", true)
      end
      for i = 1, 5 do
        record_cache("half_cache", false)
      end
      m = get_rule_metrics("half_cache")
      assert.equals(50, m.cache.hit_rate)
      clear()
      for i = 1, 10 do
        record_cache("no_cache", false)
      end
      m = get_rule_metrics("no_cache")
      return assert.equals(0, m.cache.hit_rate)
    end)
    return it("tracks cache independently per rule", function()
      for i = 1, 10 do
        record_cache("rule_x", true)
      end
      for i = 1, 5 do
        record_cache("rule_y", false)
      end
      local x = get_rule_metrics("rule_x")
      local y = get_rule_metrics("rule_y")
      assert.equals(10, x.cache.hits)
      assert.equals(0, x.cache.misses)
      assert.equals(0, y.cache.hits)
      return assert.equals(5, y.cache.misses)
    end)
  end)
  describe("TTL metrics integration", function()
    it("records TTL values from DNS responses", function()
      record_ttl("ttl_rule", 60)
      record_ttl("ttl_rule", 3600)
      record_ttl("ttl_rule", 86400)
      local m = get_rule_metrics("ttl_rule")
      assert.equals(60, m.ttl.min)
      assert.equals(86400, m.ttl.max)
      return assert.equals(30020, m.ttl.avg)
    end)
    it("handles realistic TTL distribution", function()
      local ttls = {
        300,
        300,
        600,
        300,
        3600,
        60,
        300,
        900,
        60,
        86400
      }
      for _index_0 = 1, #ttls do
        local ttl = ttls[_index_0]
        record_ttl("realistic_ttl", ttl)
      end
      local m = get_rule_metrics("realistic_ttl")
      assert.equals(60, m.ttl.min)
      assert.equals(86400, m.ttl.max)
      return assert.equals(9282, m.ttl.avg)
    end)
    return it("keeps only last 100 TTL samples", function()
      for i = 1, 150 do
        record_ttl("high_volume_rule", i * 10)
      end
      local m = get_rule_metrics("high_volume_rule")
      assert.equals(510, m.ttl.min)
      return assert.equals(1500, m.ttl.max)
    end)
  end)
  describe("combined metrics scenarios", function()
    it("tracks complete lifecycle of a rule", function()
      for req = 1, 10 do
        if req <= 7 then
          record_verdict("facebook_rule", "allow")
        else
          record_verdict("facebook_rule", "refuse")
        end
      end
      for req = 1, 8 do
        record_cache("facebook_rule", true)
      end
      for req = 1, 2 do
        record_cache("facebook_rule", false)
      end
      record_ttl("facebook_rule", 300)
      record_ttl("facebook_rule", 300)
      record_ttl("facebook_rule", 3600)
      local m = get_rule_metrics("facebook_rule")
      assert.equals(7, m.verdicts.allow)
      assert.equals(3, m.verdicts.refuse)
      assert.equals(8, m.cache.hits)
      assert.equals(2, m.cache.misses)
      assert.equals(80, m.cache.hit_rate)
      assert.equals(300, m.ttl.min)
      return assert.equals(3600, m.ttl.max)
    end)
    it("separates metrics for different rules in same session", function()
      for i = 1, 8 do
        record_verdict("allow_https", "allow")
      end
      for i = 1, 1 do
        record_verdict("allow_https", "refuse")
      end
      for i = 1, 2 do
        record_verdict("block_ads", "allow")
      end
      for i = 1, 8 do
        record_verdict("block_ads", "refuse")
      end
      for i = 1, 5 do
        record_verdict("dnsonly_china", "dnsonly")
      end
      local r1 = get_rule_metrics("allow_https")
      local r2 = get_rule_metrics("block_ads")
      local r3 = get_rule_metrics("dnsonly_china")
      assert.equals(8, r1.verdicts.allow)
      assert.equals(1, r1.verdicts.refuse)
      assert.equals(0, r1.verdicts.dnsonly)
      assert.equals(2, r2.verdicts.allow)
      assert.equals(8, r2.verdicts.refuse)
      assert.equals(0, r2.verdicts.dnsonly)
      assert.equals(0, r3.verdicts.allow)
      assert.equals(0, r3.verdicts.refuse)
      return assert.equals(5, r3.verdicts.dnsonly)
    end)
    return it("handles mixed metrics across rules", function()
      local rules_data = {
        rule_1 = {
          verdicts = {
            allow = 100,
            refuse = 5
          },
          cache_hits = 80,
          cache_misses = 25,
          ttls = {
            60,
            300,
            3600
          }
        },
        rule_2 = {
          verdicts = {
            allow = 50,
            refuse = 50
          },
          cache_hits = 40,
          cache_misses = 60,
          ttls = {
            120,
            7200
          }
        },
        rule_3 = {
          verdicts = {
            allow = 200,
            refuse = 0
          },
          cache_hits = 150,
          cache_misses = 50,
          ttls = {
            1800,
            86400
          }
        }
      }
      for i = 1, 100 do
        record_verdict("rule_1", "allow")
      end
      for i = 1, 5 do
        record_verdict("rule_1", "refuse")
      end
      for i = 1, 80 do
        record_cache("rule_1", true)
      end
      for i = 1, 25 do
        record_cache("rule_1", false)
      end
      record_ttl("rule_1", 60)
      record_ttl("rule_1", 300)
      record_ttl("rule_1", 3600)
      for i = 1, 50 do
        record_verdict("rule_2", "allow")
      end
      for i = 1, 50 do
        record_verdict("rule_2", "refuse")
      end
      for i = 1, 40 do
        record_cache("rule_2", true)
      end
      for i = 1, 60 do
        record_cache("rule_2", false)
      end
      record_ttl("rule_2", 120)
      record_ttl("rule_2", 7200)
      for i = 1, 200 do
        record_verdict("rule_3", "allow")
      end
      for i = 1, 150 do
        record_cache("rule_3", true)
      end
      for i = 1, 50 do
        record_cache("rule_3", false)
      end
      record_ttl("rule_3", 1800)
      record_ttl("rule_3", 86400)
      local m1 = get_rule_metrics("rule_1")
      local m2 = get_rule_metrics("rule_2")
      local m3 = get_rule_metrics("rule_3")
      assert.equals(100, m1.verdicts.allow)
      assert.equals(5, m1.verdicts.refuse)
      assert.equals(80, m1.cache.hits)
      assert.equals(25, m1.cache.misses)
      assert.equals(60, m1.ttl.min)
      assert.equals(3600, m1.ttl.max)
      assert.equals(50, m2.verdicts.allow)
      assert.equals(50, m2.verdicts.refuse)
      assert.equals(40, m2.cache.hits)
      assert.equals(60, m2.cache.misses)
      assert.equals(120, m2.ttl.min)
      assert.equals(7200, m2.ttl.max)
      assert.equals(200, m3.verdicts.allow)
      assert.equals(0, m3.verdicts.refuse)
      assert.equals(150, m3.cache.hits)
      assert.equals(50, m3.cache.misses)
      assert.equals(1800, m3.ttl.min)
      return assert.equals(86400, m3.ttl.max)
    end)
  end)
  return describe("metrics with disabled state", function()
    it("does not record metrics when disabled", function()
      init({
        enabled = false
      })
      record_verdict("disabled_rule", "allow")
      local m = get_rule_metrics("disabled_rule")
      return assert.is_nil(m)
    end)
    return it("allows re-enabling metrics", function()
      init({
        enabled = false
      })
      record_verdict("disabled", "allow")
      init({
        enabled = true
      })
      record_verdict("enabled", "allow")
      assert.is_nil(get_rule_metrics("disabled"))
      return assert.is_not_nil(get_rule_metrics("enabled"))
    end)
  end)
end)
