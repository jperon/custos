-- tests/unit/filter/in_time_spec.moon

describe "filter.conditions.in_time", ->
  in_time = require "filter.conditions.in_time"

  describe "named time window (existing behavior)", ->
    it "matches inside time window", ->
      cfg = {
        times: {
          business_hours: {"08:00", "17:00"}
        }
      }
      factory = in_time cfg
      f = factory "business_hours"
      
      -- Create a timestamp for 10:00
      ok, msg = f {ts: os.time({year: 2024, month: 1, day: 1, hour: 10, min: 0, sec: 0})}
      assert.is_true ok
      assert.match "In time window", msg

    it "rejects outside time window", ->
      cfg = {
        times: {
          business_hours: {"08:00", "17:00"}
        }
      }
      factory = in_time cfg
      f = factory "business_hours"
      
      -- Create a timestamp for 18:00
      ok, msg = f {ts: os.time({year: 2024, month: 1, day: 1, hour: 18, min: 0, sec: 0})}
      assert.is_false ok
      assert.match "Outside time window", msg

    it "rejects undefined window", ->
      cfg = {times: {}}
      factory = in_time cfg
      f = factory "nonexistent"
      ok, msg = f {ts: os.time()}
      assert.is_false ok
      assert.match "not defined", msg

  describe "inline time window with days", ->
    it "matches inside time window on valid day", ->
      cfg = {}
      factory = in_time cfg
      f = factory { start: "08:00", end: "17:00", days: {"Mon", "Tue", "Wed", "Thu", "Fri"} }
      
      -- Monday 2024-01-01 at 10:00
      ok, msg = f {ts: os.time({year: 2024, month: 1, day: 1, hour: 10, min: 0, sec: 0})}
      assert.is_true ok
      assert.match "In time window", msg

    it "rejects outside time window", ->
      cfg = {}
      factory = in_time cfg
      f = factory { start: "08:00", end: "17:00", days: {"Mon", "Tue", "Wed", "Thu", "Fri"} }
      
      -- Monday 2024-01-01 at 18:00 (after hours)
      ok, msg = f {ts: os.time({year: 2024, month: 1, day: 1, hour: 18, min: 0, sec: 0})}
      assert.is_false ok
      assert.match "Outside time window", msg

    it "rejects on invalid day", ->
      cfg = {}
      factory = in_time cfg
      f = factory { start: "08:00", end: "17:00", days: {"Mon", "Tue", "Wed", "Thu", "Fri"} }
      
      -- Sunday 2024-01-07 at 10:00 (weekend)
      ok, msg = f {ts: os.time({year: 2024, month: 1, day: 7, hour: 10, min: 0, sec: 0})}
      assert.is_false ok
      assert.match "not a matching day", msg

    it "handles all days when days list is empty", ->
      cfg = {}
      factory = in_time cfg
      f = factory { start: "08:00", end: "17:00", days: {} }
      
      -- Sunday 2024-01-07 at 10:00 (should match since days is empty = all days)
      ok, msg = f {ts: os.time({year: 2024, month: 1, day: 7, hour: 10, min: 0, sec: 0})}
      assert.is_true ok

    it "requires start and end", ->
      cfg = {}
      factory = in_time cfg
      f = factory { start: "08:00" }
      ok, msg = f {ts: os.time()}
      assert.is_false ok
      assert.match "requires 'start' and 'end'", msg

    it "rejects invalid time format", ->
      cfg = {}
      factory = in_time cfg
      f = factory { start: "08:60", end: "17:00" }  -- invalid minute
      ok, msg = f {ts: os.time()}
      assert.is_false ok
      assert.match "Invalid time window format", msg

    it "rejects invalid day names", ->
      cfg = {}
      factory = in_time cfg
      f = factory { start: "08:00", end: "17:00", days: {"Monday"} }  -- full names not supported
      ok, msg = f {ts: os.time()}
      assert.is_false ok
      assert.match "Invalid day names", msg
