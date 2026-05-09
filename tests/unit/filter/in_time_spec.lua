return describe("filter.conditions.in_time", function()
  local in_time = require("filter.conditions.in_time")
  describe("named time window (existing behavior)", function()
    it("matches inside time window", function()
      local cfg = {
        times = {
          business_hours = {
            "08:00",
            "17:00"
          }
        }
      }
      local factory = in_time(cfg)
      local f = factory("business_hours")
      local ok, msg = f({
        ts = os.time({
          year = 2024,
          month = 1,
          day = 1,
          hour = 10,
          min = 0,
          sec = 0
        })
      })
      assert.is_true(ok)
      return assert.match("In time window", msg)
    end)
    it("rejects outside time window", function()
      local cfg = {
        times = {
          business_hours = {
            "08:00",
            "17:00"
          }
        }
      }
      local factory = in_time(cfg)
      local f = factory("business_hours")
      local ok, msg = f({
        ts = os.time({
          year = 2024,
          month = 1,
          day = 1,
          hour = 18,
          min = 0,
          sec = 0
        })
      })
      assert.is_false(ok)
      return assert.match("Outside time window", msg)
    end)
    return it("rejects undefined window", function()
      local cfg = {
        times = { }
      }
      local factory = in_time(cfg)
      local f = factory("nonexistent")
      local ok, msg = f({
        ts = os.time()
      })
      assert.is_false(ok)
      return assert.match("not defined", msg)
    end)
  end)
  return describe("inline time window with days", function()
    it("matches inside time window on valid day", function()
      local cfg = { }
      local factory = in_time(cfg)
      local f = factory({
        start = "08:00",
        ["end"] = "17:00",
        days = {
          "Mon",
          "Tue",
          "Wed",
          "Thu",
          "Fri"
        }
      })
      local ok, msg = f({
        ts = os.time({
          year = 2024,
          month = 1,
          day = 1,
          hour = 10,
          min = 0,
          sec = 0
        })
      })
      assert.is_true(ok)
      return assert.match("In time window", msg)
    end)
    it("rejects outside time window", function()
      local cfg = { }
      local factory = in_time(cfg)
      local f = factory({
        start = "08:00",
        ["end"] = "17:00",
        days = {
          "Mon",
          "Tue",
          "Wed",
          "Thu",
          "Fri"
        }
      })
      local ok, msg = f({
        ts = os.time({
          year = 2024,
          month = 1,
          day = 1,
          hour = 18,
          min = 0,
          sec = 0
        })
      })
      assert.is_false(ok)
      return assert.match("Outside time window", msg)
    end)
    it("rejects on invalid day", function()
      local cfg = { }
      local factory = in_time(cfg)
      local f = factory({
        start = "08:00",
        ["end"] = "17:00",
        days = {
          "Mon",
          "Tue",
          "Wed",
          "Thu",
          "Fri"
        }
      })
      local ok, msg = f({
        ts = os.time({
          year = 2024,
          month = 1,
          day = 7,
          hour = 10,
          min = 0,
          sec = 0
        })
      })
      assert.is_false(ok)
      return assert.match("not a matching day", msg)
    end)
    it("handles all days when days list is empty", function()
      local cfg = { }
      local factory = in_time(cfg)
      local f = factory({
        start = "08:00",
        ["end"] = "17:00",
        days = { }
      })
      local ok, msg = f({
        ts = os.time({
          year = 2024,
          month = 1,
          day = 7,
          hour = 10,
          min = 0,
          sec = 0
        })
      })
      return assert.is_true(ok)
    end)
    it("requires start and end", function()
      local cfg = { }
      local factory = in_time(cfg)
      local f = factory({
        start = "08:00"
      })
      local ok, msg = f({
        ts = os.time()
      })
      assert.is_false(ok)
      return assert.match("requires 'start' and 'end'", msg)
    end)
    it("rejects invalid time format", function()
      local cfg = { }
      local factory = in_time(cfg)
      local f = factory({
        start = "08:60",
        ["end"] = "17:00"
      })
      local ok, msg = f({
        ts = os.time()
      })
      assert.is_false(ok)
      return assert.match("Invalid time window format", msg)
    end)
    return it("rejects invalid day names", function()
      local cfg = { }
      local factory = in_time(cfg)
      local f = factory({
        start = "08:00",
        ["end"] = "17:00",
        days = {
          "Monday"
        }
      })
      local ok, msg = f({
        ts = os.time()
      })
      assert.is_false(ok)
      return assert.match("Invalid day names", msg)
    end)
  end)
end)
