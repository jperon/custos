local util = require("ipparse.lib.util")
local test
test = util.test
local tcp_stream = require("ipparse.l4.tcp_stream")
test("tcp_stream: default predicate returns each payload immediately", function()
  local s = tcp_stream.new()
  local buf, seq, first = s.feed("k", "hello", 0x10, 42)
  return assert(buf == "hello" and seq == 42 and first == true, "immediate completion failed")
end)
test("tcp_stream: accumulates until predicate passes", function()
  local s = tcp_stream.new(function(buf)
    return #buf >= 6
  end)
  assert(s.feed("k", "abc", 0x10, 1) == nil, "should be incomplete")
  local buf = s.feed("k", "defg", 0x10, 2)
  return assert(buf == "abcdefg", "expected reassembled buffer, got " .. tostring(buf))
end)
test("tcp_stream: FIN clears the session", function()
  local s = tcp_stream.new(function(buf)
    return #buf >= 6
  end)
  s.feed("k", "abc", 0x10, 1)
  s.feed("k", "", 0x01, 2)
  local buf = s.feed("k", "123456", 0x10, 3)
  return assert(buf == "123456", "buffer should only contain post-FIN data, got " .. tostring(buf))
end)
test("tcp_stream: per-session buffer is capped", function()
  local s = tcp_stream.new((function(buf)
    return #buf >= 6
  end), {
    max_buf = 8
  })
  assert(s.feed("k", "12345", 0x10, 1) == nil, "incomplete")
  assert(s.feed("k", "abcdefgh", 0x10, 2) == nil, "overflow should drop session")
  local buf = s.feed("k", "123456", 0x10, 3)
  return assert(buf == "123456", "expected fresh buffer after overflow, got " .. tostring(buf))
end)
test("tcp_stream: session count is capped (oldest dropped)", function()
  local s = tcp_stream.new((function(buf)
    return #buf >= 6
  end), {
    max_sessions = 2
  })
  s.feed("a", "abc", 0x10, 1)
  s.feed("b", "abc", 0x10, 1)
  s.feed("c", "abc", 0x10, 1)
  local buf = s.feed("c", "def", 0x10, 2)
  return assert(buf == "abcdef", "session c should have survived eviction, got " .. tostring(buf))
end)
test("tcp_stream: reset drops everything", function()
  local s = tcp_stream.new(function(buf)
    return #buf >= 6
  end)
  s.feed("k", "abc", 0x10, 1)
  s.reset()
  local buf = s.feed("k", "123456", 0x10, 2)
  return assert(buf == "123456", "buffer should only contain post-reset data, got " .. tostring(buf))
end)
test("tcp_stream: purge drops sessions older than max_age", function()
  local now = 0
  local s = tcp_stream.new((function(buf)
    return #buf >= 6
  end), {
    clock = function()
      return now, {
        clock_hz = 1000
      }
    end
  })
  s.feed("old", "abc", 0x10, 1)
  now = 5000
  s.feed("new", "abc", 0x10, 1)
  s.purge(3)
  local buf = s.feed("new", "def", 0x10, 2)
  assert(buf == "abcdef", "recent session should survive purge, got " .. tostring(buf))
  buf = s.feed("old", "def", 0x10, 2)
  return assert(buf == nil, "old session should have been purged, got " .. tostring(buf))
end)
test("tcp_stream: clock_hz without clock raises", function()
  local ok, err = pcall(tcp_stream.new, nil, {
    clock_hz = 1000
  })
  assert(not ok, "expected an error when clock_hz is given without clock")
  return assert(tostring(err):find("clock_hz"), "error should mention clock_hz, got " .. tostring(err))
end)
return util.summary("l4/tcp_stream")
