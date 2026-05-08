local util = require("ipparse.lib.util")
local test
test = util.test
local bidirectional, memo, memoN, iter, range, opairs, zero_indexed
do
  local _obj_0 = require("ipparse.fun")
  bidirectional, memo, memoN, iter, range, opairs, zero_indexed = _obj_0.bidirectional, _obj_0.memo, _obj_0.memoN, _obj_0.iter, _obj_0.range, _obj_0.opairs, _obj_0.zero_indexed
end
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
return util.summary("fun")
