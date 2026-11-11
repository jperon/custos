local util = require("ipparse.lib.util")
local test
test = util.test
local bidirectional, memo, memoN, iter, range, opairs, zero_indexed
do
  local _obj_0 = require("ipparse.fun")
  bidirectional, memo, memoN, iter, range, opairs, zero_indexed = _obj_0.bidirectional, _obj_0.memo, _obj_0.memoN, _obj_0.iter, _obj_0.range, _obj_0.opairs, _obj_0.zero_indexed
end
local fun = require("ipparse.fun")
test("bidirectional forward lookup", function()
  local t = bidirectional({
    a = 1,
    b = 2
  })
  assert(t.a == 1, "t.a should be 1")
  return assert(t.b == 2, "t.b should be 2")
end)
test("bidirectional reverse lookup", function()
  local t = bidirectional({
    a = 1,
    b = 2
  })
  assert(t[1] == "a", "t[1] should be 'a', got '" .. tostring(t[1]) .. "'")
  return assert(t[2] == "b", "t[2] should be 'b', got '" .. tostring(t[2]) .. "'")
end)
test("memo caches single-arg function", function()
  local count = 0
  local fn = memo(function(x)
    count = count + 1
    return x * 2
  end)
  assert(fn(5) == 10, "first call should return 10")
  assert(fn(5) == 10, "second call should still return 10")
  return assert(count == 1, "original called " .. tostring(count) .. " times, expected 1")
end)
test("memoN caches multi-arg function", function()
  local count = 0
  local fn = memoN(function(a, b)
    count = count + 1
    return a + b
  end)
  assert(fn(3, 4) == 7, "first call should return 7")
  assert(fn(3, 4) == 7, "second call should still return 7")
  return assert(count == 1, "memoN: original called " .. tostring(count) .. " times, expected 1")
end)
test("iter toarray basic", function()
  local arr = iter({
    10,
    20,
    30
  }):toarray()
  assert(#arr == 3, "expected 3 elements, got " .. tostring(#arr))
  assert(arr[1] == 10, "arr[1] should be 10")
  assert(arr[2] == 20, "arr[2] should be 20")
  return assert(arr[3] == 30, "arr[3] should be 30")
end)
test("iter map doubles values", function()
  local arr = iter({
    1,
    2,
    3
  }):map(function(x)
    return x * 2
  end):toarray()
  assert(arr[1] == 2, "arr[1] should be 2")
  assert(arr[2] == 4, "arr[2] should be 4")
  return assert(arr[3] == 6, "arr[3] should be 6")
end)
test("iter filter keeps evens", function()
  local arr = iter({
    1,
    2,
    3,
    4,
    5
  }):filter(function(x)
    return x % 2 == 0
  end):toarray()
  assert(#arr == 2, "expected 2 elements, got " .. tostring(#arr))
  assert(arr[1] == 2, "arr[1] should be 2")
  return assert(arr[2] == 4, "arr[2] should be 4")
end)
test("iter reduce sums values", function()
  local sum = iter({
    1,
    2,
    3,
    4,
    5
  }):reduce(function(acc, v)
    return acc + v
  end)
  return assert(sum == 15, "sum should be 15, got " .. tostring(sum))
end)
test("iter take first N", function()
  local arr = iter({
    1,
    2,
    3,
    4,
    5
  }):take(3):toarray()
  assert(#arr == 3, "expected 3 elements, got " .. tostring(#arr))
  assert(arr[1] == 1, "arr[1] should be 1")
  return assert(arr[3] == 3, "arr[3] should be 3")
end)
test("range generates 1..5", function()
  local arr = { }
  for i in range(5) do
    arr[#arr + 1] = i
  end
  assert(#arr == 5, "expected 5 elements, got " .. tostring(#arr))
  assert(arr[1] == 1, "arr[1] should be 1")
  return assert(arr[5] == 5, "arr[5] should be 5")
end)
test("range with start and end", function()
  local arr = { }
  for i in range(2, 5) do
    arr[#arr + 1] = i
  end
  assert(arr[1] == 2, "arr[1] should be 2")
  return assert(arr[4] == 5, "arr[4] should be 5")
end)
test("opairs returns sorted keys", function()
  local t = {
    c = 3,
    a = 1,
    b = 2
  }
  local keys = { }
  for k, v in opairs(t) do
    keys[#keys + 1] = k
  end
  assert(keys[1] == "a", "keys[1] should be 'a', got '" .. tostring(keys[1]) .. "'")
  assert(keys[2] == "b", "keys[2] should be 'b'")
  return assert(keys[3] == "c", "keys[3] should be 'c'")
end)
test("zero_indexed copies t[1] to t[0]", function()
  local t = zero_indexed({
    "x",
    "y",
    "z"
  })
  return assert(t[0] == "x", "t[0] should be 'x', got '" .. tostring(t[0]) .. "'")
end)
test("bidirectional invalidates stale cache on key modification", function()
  local t = bidirectional({
    a = 1
  })
  assert(t[1] == "a", "t[1] should be 'a', got '" .. tostring(t[1]) .. "'")
  t.a = 2
  assert(t[1] == nil, "t[1] should be nil after t.a changed, got '" .. tostring(t[1]) .. "'")
  return assert(t[2] == "a", "t[2] should be 'a' after change, got '" .. tostring(t[2]) .. "'")
end)
test("bidirectional drops cache for deleted key", function()
  local t = bidirectional({
    a = 1
  })
  assert(t[1] == "a", "t[1] should be 'a', got '" .. tostring(t[1]) .. "'")
  t.a = nil
  return assert(t[1] == nil, "t[1] should be nil after key deletion, got '" .. tostring(t[1]) .. "'")
end)
test("bidirectional cache cycle after deletion", function()
  local t = bidirectional({
    x = "y",
    y = "x"
  })
  assert(t["y"] == "x", "t['y'] should be 'x', got '" .. tostring(t['y']) .. "'")
  assert(t["x"] == "y", "t['x'] should be 'y', got '" .. tostring(t['x']) .. "'")
  t.x = nil
  t.y = nil
  return assert(t["y"] == nil, "t['y'] should be nil after deletion, got '" .. tostring(t['y']) .. "'")
end)
test("bidirectional non-regression forward and reverse lookup", function()
  local t = bidirectional({
    a = 1,
    b = 2
  })
  assert(t.a == 1, "t.a should be 1")
  assert(t.b == 2, "t.b should be 2")
  assert(t[1] == "a", "t[1] should be 'a'")
  return assert(t[2] == "b", "t[2] should be 'b'")
end)
test("bidirectional reverse sees key added later", function()
  local t = bidirectional({
    a = 1
  })
  t.b = 2
  return assert(t[2] == "b", "t[2] should be 'b' after adding t.b, got '" .. tostring(t[2]) .. "'")
end)
test("bidirectional pairs only sees real entries", function()
  local t = bidirectional({
    a = 1,
    b = 2
  })
  local _ = t[1]
  _ = t[2]
  local n = 0
  for k, v in pairs(t) do
    n = n + 1
  end
  return assert(n == 2, "pairs should see 2 entries, got " .. tostring(n))
end)
test("protected only prints a traceback when leak_debug is set", function()
  local original_print = _G.print
  local calls = 0
  _G.print = function(...)
    calls = calls + 1
  end
  local ok, err = pcall(function()
    assert(rawget(fun, "leak_debug") == nil, "leak_debug should be unset")
    local p = fun.protected(function()
      return 1, 2
    end)
    local a, b = p()
    assert(a == 1 and b == 2, "protected should return fn values")
    assert(calls == 0, "expected no print call, got " .. tostring(calls))
    p = fun.protected(function()
      return error("boom")
    end)
    local r = p()
    assert(r == nil, "protected should return nil on error")
    assert(calls == 1, "expected 1 print call, got " .. tostring(calls))
    calls = 0
    fun.leak_debug = true
    p = fun.protected(function()
      return error("boom")
    end)
    r = p()
    assert(r == nil, "protected should return nil on error")
    assert(calls == 2, "expected 2 print calls, got " .. tostring(calls))
    fun.leak_debug = nil
  end)
  _G.print = original_print
  return assert(ok, err)
end)
test("zero_indexed shifts every element down by one index", function()
  local arr = {
    "a",
    "b",
    "c"
  }
  zero_indexed(arr)
  assert(arr[0] == "a", "arr[0] should be 'a', got '" .. tostring(arr[0]) .. "'")
  assert(arr[1] == "b", "arr[1] should be 'b', got '" .. tostring(arr[1]) .. "'")
  assert(arr[2] == "c", "arr[2] should be 'c', got '" .. tostring(arr[2]) .. "'")
  return assert(arr[3] == nil, "arr[3] should be nil, got '" .. tostring(arr[3]) .. "'")
end)
test("protected forwards multiple arguments and returns with nil holes", function()
  local p = fun.protected(function(a, b, c)
    return c, b, a
  end)
  local r1, r2, r3 = p(1, nil, 3)
  assert(r1 == 3, "first return should be 3, got '" .. tostring(r1) .. "'")
  assert(r2 == nil, "second return should be nil, got '" .. tostring(r2) .. "'")
  return assert(r3 == 1, "third return should be 1, got '" .. tostring(r3) .. "'")
end)
test("protected returns no value on error and calls op", function()
  local original_print = _G.print
  _G.print = function()
    return 0
  end
  local op_calls = 0
  local p = fun.protected((function()
    return error("boom")
  end), (function()
    op_calls = op_calls + 1
  end))
  local n = select("#", p())
  _G.print = original_print
  assert(n == 0, "protected should return no value on error, got " .. tostring(n))
  return assert(op_calls == 1, "op should be called once, got " .. tostring(op_calls))
end)
test("protected forwards 26 arguments and returns", function()
  local p = fun.protected(function(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z)
    return a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z
  end)
  local r = {
    p(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26)
  }
  assert(#r == 26, "expected 26 returns, got " .. tostring(#r))
  assert(r[1] == 1, "r[1] should be 1, got '" .. tostring(r[1]) .. "'")
  return assert(r[26] == 26, "r[26] should be 26, got '" .. tostring(r[26]) .. "'")
end)
test("iter with a positive step yields every other element", function()
  local arr = iter({
    10,
    20,
    30,
    40
  }, 2):toarray()
  assert(#arr == 2, "expected 2 elements, got " .. tostring(#arr))
  return assert(arr[1] == 20 and arr[2] == 40, "step iteration mismatch")
end)
test("iter any returns the first match", function()
  local v = iter({
    1,
    2,
    3,
    4
  }):any(function(x)
    return x % 2 == 0
  end)
  return assert(v == 2, "expected 2, got " .. tostring(v))
end)
test("iter getn returns the nth matching element", function()
  local v = iter({
    10,
    20,
    30
  }):getn(2, function(x)
    return true
  end)
  return assert(v == 20, "expected 20, got " .. tostring(v))
end)
test("iter each visits every element and returns the iterator", function()
  local seen = { }
  local it = iter({
    1,
    2,
    3
  })
  local r = it:each(function(v)
    seen[#seen + 1] = v
  end)
  assert(#seen == 3, "expected 3 visited elements, got " .. tostring(#seen))
  assert(seen[1] == 1 and seen[3] == 3, "visited values mismatch")
  return assert(r == it, "each should return the iterator")
end)
test("iter imap exposes a one-based index", function()
  local arr = iter({
    10,
    20,
    30
  }):imap(function(v, i)
    return v + i
  end):toarray()
  return assert(arr[1] == 11 and arr[2] == 22 and arr[3] == 33, "imap mismatch")
end)
test("iter reduce with an initial value", function()
  local sum = iter({
    1,
    2,
    3
  }):reduce((function(acc, v)
    return acc + v
  end), 10)
  return assert(sum == 16, "sum should be 16, got " .. tostring(sum))
end)
test("range with a step", function()
  local arr = { }
  for i in range(1, 10, 3) do
    arr[#arr + 1] = i
  end
  assert(#arr == 4, "expected 4 elements, got " .. tostring(#arr))
  return assert(arr[1] == 1 and arr[4] == 10, "stepped range mismatch")
end)
test("generate wraps a producer function", function()
  local n = 0
  local gen = fun.generate(function()
    n = n + 1
    if n <= 3 then
      return n
    end
  end)
  local arr = gen:toarray()
  assert(#arr == 3, "expected 3 elements, got " .. tostring(#arr))
  return assert(arr[1] == 1 and arr[3] == 3, "generated values mismatch")
end)
test("memo forwards nil without caching", function()
  local fn = memo(function(x)
    if x == nil then
      return 42
    else
      return x * 2
    end
  end)
  assert(fn(nil) == 42, "nil should be forwarded to the original")
  return assert(fn(5) == 10, "non-nil should still be cached")
end)
test("memoN handles nil arguments", function()
  local count = 0
  local fn = memoN(function(a, b)
    count = count + 1
    return (a or 0) + (b or 0)
  end)
  assert(fn(1, nil) == 1, "expected 1")
  assert(fn(1, nil) == 1, "expected cached 1")
  assert(fn(nil, nil) == 0, "expected 0 for two nils")
  return assert(count == 2, "original called " .. tostring(count) .. " times, expected 2")
end)
test("opairs sorts mixed key types without error", function()
  local keys = { }
  for k in opairs({
    [1] = "number",
    a = "string"
  }) do
    keys[#keys + 1] = k
  end
  return assert(#keys == 2, "expected 2 keys, got " .. tostring(#keys))
end)
test("fun.map table shortcut maps an array", function()
  local arr = fun.map({
    1,
    2,
    3
  }, function(x)
    return x * 2
  end):toarray()
  assert(#arr == 3, "expected 3 elements, got " .. tostring(#arr))
  return assert(arr[1] == 2 and arr[3] == 6, "table shortcut map mismatch")
end)
test("fun.tables loads alone and exposes its functions", function()
  local t = require("ipparse.fun.tables")
  assert(type(t.bidirectional) == "function", "tables.bidirectional should be a function")
  assert(type(t.zero_indexed) == "function", "tables.zero_indexed should be a function")
  return assert(type(t.opairs) == "function", "tables.opairs should be a function")
end)
test("fun.memo loads alone and exposes its functions", function()
  local m = require("ipparse.fun.memo")
  assert(type(m.memo) == "function", "memo.memo should be a function")
  return assert(type(m.memoN) == "function", "memo.memoN should be a function")
end)
test("fun.iter loads alone and exposes its functions", function()
  local m = require("ipparse.fun.iter")
  assert(type(m.iter) == "table", "iter.iter should be a table")
  assert(type(m.wrap) == "function", "iter.wrap should be a function")
  assert(type(m.generate) == "function", "iter.generate should be a function")
  return assert(type(m.range) == "function", "iter.range should be a function")
end)
test("fun.protected loads alone and exposes protected and leak_debug", function()
  local m = require("ipparse.fun.protected")
  assert(type(m.protected) == "function", "protected.protected should be a function")
  assert(rawget(m, "leak_debug") == nil, "protected.leak_debug should start unset")
  m.leak_debug = true
  assert(m.leak_debug == true, "protected.leak_debug should be writable")
  m.leak_debug = nil
end)
test("fun facade re-exports the same functions as the submodules", function()
  local tables = require("ipparse.fun.tables")
  local memo_mod = require("ipparse.fun.memo")
  local iter_mod = require("ipparse.fun.iter")
  local protected_mod = require("ipparse.fun.protected")
  assert(fun.bidirectional == tables.bidirectional, "bidirectional identity mismatch")
  assert(fun.zero_indexed == tables.zero_indexed, "zero_indexed identity mismatch")
  assert(fun.opairs == tables.opairs, "opairs identity mismatch")
  assert(fun.memo == memo_mod.memo, "memo identity mismatch")
  assert(fun.memoN == memo_mod.memoN, "memoN identity mismatch")
  assert(fun.iter == iter_mod.iter, "iter identity mismatch")
  assert(fun.wrap == iter_mod.wrap, "wrap identity mismatch")
  assert(fun.generate == iter_mod.generate, "generate identity mismatch")
  assert(fun.range == iter_mod.range, "range identity mismatch")
  return assert(fun.protected == protected_mod.protected, "protected identity mismatch")
end)
return util.summary("fun")
