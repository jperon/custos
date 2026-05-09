return describe("time-based rule enforcement", function()
  local rule = require("filter.rule")
  describe("named time windows", function()
    it("allows DNS query during work hours", function()
      local cfg = {
        times = {
          business_hours = {
            "08:00",
            "17:00"
          }
        },
        rules = {
          {
            description = "Allow during business hours",
            actions = {
              "allow"
            },
            conditions = {
              {
                to_domain = "work.com"
              },
              {
                in_time = "business_hours"
              }
            }
          }
        },
        decision = {
          first_match_wins = true
        }
      }
      local rules = rule.compile_rules(cfg)
      local req = {
        domain = "work.com",
        ts = os.time({
          year = 2024,
          month = 1,
          day = 1,
          hour = 10,
          min = 0,
          sec = 0
        })
      }
      local verdict, msg = rule.decide(rules, req)
      return assert.is_true(verdict, msg)
    end)
    return it("denies DNS query outside work hours", function()
      local cfg = {
        times = {
          business_hours = {
            "08:00",
            "17:00"
          }
        },
        rules = {
          {
            description = "Allow during business hours",
            actions = {
              "allow"
            },
            conditions = {
              {
                to_domain = "work.com"
              },
              {
                in_time = "business_hours"
              }
            }
          }
        },
        decision = {
          first_match_wins = true
        }
      }
      local rules = rule.compile_rules(cfg)
      local req = {
        domain = "work.com",
        ts = os.time({
          year = 2024,
          month = 1,
          day = 1,
          hour = 18,
          min = 0,
          sec = 0
        })
      }
      local verdict, msg = rule.decide(rules, req)
      return assert.is_false(verdict, msg)
    end)
  end)
  describe("inline time windows with days", function()
    it("allows DNS query on weekday during work hours", function()
      local cfg = {
        rules = {
          {
            description = "Allow Mon-Fri 8am-5pm",
            actions = {
              "allow"
            },
            conditions = {
              {
                to_domain = "youtube.com"
              },
              {
                in_time = {
                  start = "08:00",
                  ["end"] = "17:00",
                  days = {
                    "Mon",
                    "Tue",
                    "Wed",
                    "Thu",
                    "Fri"
                  }
                }
              }
            }
          }
        },
        decision = {
          first_match_wins = true
        }
      }
      local rules = rule.compile_rules(cfg)
      local req = {
        domain = "youtube.com",
        ts = os.time({
          year = 2024,
          month = 1,
          day = 1,
          hour = 10,
          min = 0,
          sec = 0
        })
      }
      local verdict, msg = rule.decide(rules, req)
      return assert.is_true(verdict, msg)
    end)
    it("denies DNS query on weekend even during work hours", function()
      local cfg = {
        rules = {
          {
            description = "Allow Mon-Fri 8am-5pm",
            actions = {
              "allow"
            },
            conditions = {
              {
                to_domain = "youtube.com"
              },
              {
                in_time = {
                  start = "08:00",
                  ["end"] = "17:00",
                  days = {
                    "Mon",
                    "Tue",
                    "Wed",
                    "Thu",
                    "Fri"
                  }
                }
              }
            }
          }
        },
        decision = {
          first_match_wins = true
        }
      }
      local rules = rule.compile_rules(cfg)
      local req = {
        domain = "youtube.com",
        ts = os.time({
          year = 2024,
          month = 1,
          day = 7,
          hour = 10,
          min = 0,
          sec = 0
        })
      }
      local verdict, msg = rule.decide(rules, req)
      return assert.is_false(verdict, msg)
    end)
    return it("denies DNS query after work hours on weekday", function()
      local cfg = {
        rules = {
          {
            description = "Allow Mon-Fri 8am-5pm",
            actions = {
              "allow"
            },
            conditions = {
              {
                to_domain = "youtube.com"
              },
              {
                in_time = {
                  start = "08:00",
                  ["end"] = "17:00",
                  days = {
                    "Mon",
                    "Tue",
                    "Wed",
                    "Thu",
                    "Fri"
                  }
                }
              }
            }
          }
        },
        decision = {
          first_match_wins = true
        }
      }
      local rules = rule.compile_rules(cfg)
      local req = {
        domain = "youtube.com",
        ts = os.time({
          year = 2024,
          month = 1,
          day = 1,
          hour = 18,
          min = 0,
          sec = 0
        })
      }
      local verdict, msg = rule.decide(rules, req)
      return assert.is_false(verdict, msg)
    end)
  end)
  return describe("time windows with default allow-all rule", function()
    return it("allows domain outside time window if default rule allows", function()
      local cfg = {
        rules = {
          {
            description = "Allow youtube only during work hours",
            actions = {
              "deny"
            },
            conditions = {
              {
                to_domain = "youtube.com"
              },
              {
                in_time = {
                  start = "08:00",
                  ["end"] = "17:00",
                  days = {
                    "Mon",
                    "Tue",
                    "Wed",
                    "Thu",
                    "Fri"
                  }
                }
              }
            }
          },
          {
            description = "Default allow all other domains",
            actions = {
              "allow"
            },
            conditions = { }
          }
        },
        decision = {
          first_match_wins = true
        }
      }
      local rules = rule.compile_rules(cfg)
      local req = {
        domain = "google.com",
        ts = os.time({
          year = 2024,
          month = 1,
          day = 7,
          hour = 10,
          min = 0,
          sec = 0
        })
      }
      local verdict, msg = rule.decide(rules, req)
      return assert.is_true(verdict)
    end)
  end)
end)
