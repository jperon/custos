-- tests/unit/filter/time_rule_integration_spec.moon
-- Integration tests for time-based rule enforcement

describe "time-based rule enforcement", ->
  rule = require "filter.rule"

  describe "named time windows", ->
    it "allows DNS query during work hours", ->
      cfg = {
        times: {
          business_hours: {"08:00", "17:00"}
        }
        rules: {
          {
            description: "Allow during business hours"
            actions: {"allow"}
            conditions: {
              { to_domain: "work.com" }
              { in_time: "business_hours" }
            }
          }
        }
        decision: {
          first_match_wins: true
        }
      }
      rules = rule.compile_rules cfg
      
      -- Test at 10:00 (inside hours)
      req = {
        domain: "work.com"
        ts: os.time({year: 2024, month: 1, day: 1, hour: 10, min: 0, sec: 0})
      }
      verdict, msg = rule.decide rules, req
      assert.is_true verdict, msg

    it "denies DNS query outside work hours", ->
      cfg = {
        times: {
          business_hours: {"08:00", "17:00"}
        }
        rules: {
          {
            description: "Allow during business hours"
            actions: {"allow"}
            conditions: {
              { to_domain: "work.com" }
              { in_time: "business_hours" }
            }
          }
        }
        decision: {
          first_match_wins: true
        }
      }
      rules = rule.compile_rules cfg
      
      -- Test at 18:00 (outside hours)
      req = {
        domain: "work.com"
        ts: os.time({year: 2024, month: 1, day: 1, hour: 18, min: 0, sec: 0})
      }
      verdict, msg = rule.decide rules, req
      -- Rule doesn't match outside hours, so default deny
      assert.is_false verdict, msg

  describe "inline time windows with days", ->
    it "allows DNS query on weekday during work hours", ->
      cfg = {
        rules: {
          {
            description: "Allow Mon-Fri 8am-5pm"
            actions: {"allow"}
            conditions: {
              { to_domain: "youtube.com" }
              { in_time: { start: "08:00", end: "17:00", days: {"Mon", "Tue", "Wed", "Thu", "Fri"} } }
            }
          }
        }
        decision: {
          first_match_wins: true
        }
      }
      rules = rule.compile_rules cfg
      
      -- Monday 2024-01-01 at 10:00
      req = {
        domain: "youtube.com"
        ts: os.time({year: 2024, month: 1, day: 1, hour: 10, min: 0, sec: 0})
      }
      verdict, msg = rule.decide rules, req
      assert.is_true verdict, msg

    it "denies DNS query on weekend even during work hours", ->
      cfg = {
        rules: {
          {
            description: "Allow Mon-Fri 8am-5pm"
            actions: {"allow"}
            conditions: {
              { to_domain: "youtube.com" }
              { in_time: { start: "08:00", end: "17:00", days: {"Mon", "Tue", "Wed", "Thu", "Fri"} } }
            }
          }
        }
        decision: {
          first_match_wins: true
        }
      }
      rules = rule.compile_rules cfg
      
      -- Sunday 2024-01-07 at 10:00
      req = {
        domain: "youtube.com"
        ts: os.time({year: 2024, month: 1, day: 7, hour: 10, min: 0, sec: 0})
      }
      verdict, msg = rule.decide rules, req
      -- Rule doesn't match on weekend, so default deny
      assert.is_false verdict, msg

    it "denies DNS query after work hours on weekday", ->
      cfg = {
        rules: {
          {
            description: "Allow Mon-Fri 8am-5pm"
            actions: {"allow"}
            conditions: {
              { to_domain: "youtube.com" }
              { in_time: { start: "08:00", end: "17:00", days: {"Mon", "Tue", "Wed", "Thu", "Fri"} } }
            }
          }
        }
        decision: {
          first_match_wins: true
        }
      }
      rules = rule.compile_rules cfg
      
      -- Monday 2024-01-01 at 18:00
      req = {
        domain: "youtube.com"
        ts: os.time({year: 2024, month: 1, day: 1, hour: 18, min: 0, sec: 0})
      }
      verdict, msg = rule.decide rules, req
      -- Rule doesn't match after hours, so default deny
      assert.is_false verdict, msg

  describe "time windows with default allow-all rule", ->
    it "allows domain outside time window if default rule allows", ->
      cfg = {
        rules: {
          {
            description: "Allow youtube only during work hours"
            actions: {"deny"}
            conditions: {
              { to_domain: "youtube.com" }
              { in_time: { start: "08:00", end: "17:00", days: {"Mon", "Tue", "Wed", "Thu", "Fri"} } }
            }
          }
          {
            description: "Default allow all other domains"
            actions: {"allow"}
            conditions: {
              -- no conditions = always match
            }
          }
        }
        decision: {
          first_match_wins: true
        }
      }
      rules = rule.compile_rules cfg
      
      -- Sunday at 10:00
      req = {
        domain: "google.com"
        ts: os.time({year: 2024, month: 1, day: 7, hour: 10, min: 0, sec: 0})
      }
      verdict, msg = rule.decide rules, req
      assert.is_true verdict
