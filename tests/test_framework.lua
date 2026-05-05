passed, failed = 0, 0
current_suite = nil
local deep_eq
deep_eq = function(a, b)
  local ta, tb = type(a), type(b)
  if not (ta == tb) then
    return false
  end
  if ta == "table" then
    local ka, kb = 0, 0
    for _ in pairs(a) do
      ka = ka + 1
    end
    for _ in pairs(b) do
      kb = kb + 1
    end
    if not (ka == kb) then
      return false
    end
    for k, v in pairs(a) do
      if not (deep_eq(v, b[k])) then
        return false
      end
    end
    return true
  end
  return a == b
end
local assert_eq
assert_eq = function(got, expected, msg)
  if not (deep_eq(got, expected)) then
    return error(tostring(msg or "assertion échouée") .. "\n       got:      " .. tostring(tostring(got)) .. "\n       expected: " .. tostring(tostring(expected)), 2)
  end
end
local assert_ne
assert_ne = function(got, unexpected, msg)
  if deep_eq(got, unexpected) then
    return error(tostring(msg or "assertion échouée") .. "\n       got:      " .. tostring(tostring(got)) .. "\n       unexpected: " .. tostring(tostring(unexpected)), 2)
  end
end
local assert_true
assert_true = function(v, msg)
  if not (v) then
    return error(tostring(msg or "expected true") .. "\n       got: " .. tostring(tostring(v)), 2)
  end
end
local assert_false
assert_false = function(v, msg)
  if v then
    return error(tostring(msg or "expected false") .. "\n       got: " .. tostring(tostring(v)), 2)
  end
end
local assert_nil
assert_nil = function(v, msg)
  if not (v == nil) then
    return error(tostring(msg or "expected nil") .. "\n       got: " .. tostring(tostring(v)), 2)
  end
end
local assert_not_nil
assert_not_nil = function(v, msg)
  if v == nil then
    return error(tostring(msg or "expected non-nil") .. "\n       got: nil", 2)
  end
end
local assert_contains
assert_contains = function(haystack, needle, msg)
  if not (haystack and tostring(haystack):find(tostring(needle), 1, true)) then
    return error(tostring(msg or "missing substring") .. "\n       needle: " .. tostring(tostring(needle)) .. "\n       haystack: " .. tostring(tostring(haystack)), 2)
  end
end
local assert_matches
assert_matches = function(haystack, pattern, msg)
  if not (haystack and tostring(haystack):match(pattern)) then
    return error(tostring(msg or "no match") .. "\n       pattern: " .. tostring(pattern) .. "\n       haystack: " .. tostring(tostring(haystack)), 2)
  end
end
local assert_throws
assert_throws = function(pattern, fn)
  local ok, err = pcall(fn)
  if ok then
    error("expected error matching '" .. tostring(pattern) .. "', but no error was raised", 2)
  end
  if not (err and tostring(err):find(pattern, 1, true)) then
    return error("expected error matching '" .. tostring(pattern) .. "', got: " .. tostring(tostring(err)), 2)
  end
end
local stub_module
stub_module = function(name, mock)
  local orig = package.loaded[name]
  package.loaded[name] = mock
  return function()
    package.loaded[name] = orig
  end
end
local with_stubs
with_stubs = function(stubs, fn)
  local restore_fns = { }
  for name, mock in pairs(stubs) do
    table.insert(restore_fns, stub_module(name, mock))
  end
  local ok, err = pcall(fn)
  for _index_0 = 1, #restore_fns do
    local r = restore_fns[_index_0]
    r()
  end
  if not (ok) then
    return error(err, 2)
  end
end
local test
test = function(name, fn)
  local ok, err = pcall(fn)
  if ok then
    passed = passed + 1
    if current_suite then
      return io.write("      ✓ " .. tostring(name) .. "\n")
    else
      return io.write("  ✓ " .. tostring(name) .. "\n")
    end
  else
    failed = failed + 1
    if current_suite then
      return io.write("      ✗ " .. tostring(name) .. "\n         " .. tostring(tostring(err):gsub("\n", "\n         ")) .. "\n")
    else
      return io.write("  ✗ " .. tostring(name) .. "\n     " .. tostring(tostring(err):gsub("\n", "\n     ")) .. "\n")
    end
  end
end
local run_suite
run_suite = function(suite_name, tests)
  local old_suite = current_suite
  current_suite = suite_name
  io.write("\n━━━ " .. tostring(suite_name) .. " ━━━\n")
  local suite_passed, suite_failed
  suite_passed, suite_failed = 0, 0
  for _index_0 = 1, #tests do
    local t = tests[_index_0]
    local before_passed, before_failed = passed, failed
    test(t[1], t[2])
    suite_passed = suite_passed + (passed - before_passed)
    suite_failed = suite_failed + (failed - before_failed)
  end
  current_suite = old_suite
  io.write("  " .. tostring(suite_passed) .. " passé(s), " .. tostring(suite_failed) .. " échec(s)\n")
  return {
    passed = suite_passed,
    failed = suite_failed
  }
end
local summary
summary = function()
  io.write("\n")
  io.write("══════════════════════════════════════════════════\n")
  if failed == 0 then
    io.write("  ✅ Tous les tests passés : " .. tostring(passed) .. " test(s)\n")
  else
    io.write("  ⚠️  " .. tostring(passed) .. " passé(s), " .. tostring(failed) .. " échec(s)\n")
  end
  io.write("══════════════════════════════════════════════════\n")
  return io.write("\n")
end
local reset
reset = function()
  passed, failed = 0, 0
end
return {
  test = test,
  run_suite = run_suite,
  summary = summary,
  reset = reset,
  assert_eq = assert_eq,
  assert_ne = assert_ne,
  assert_true = assert_true,
  assert_false = assert_false,
  assert_nil = assert_nil,
  assert_not_nil = assert_not_nil,
  assert_contains = assert_contains,
  assert_matches = assert_matches,
  assert_throws = assert_throws,
  stub_module = stub_module,
  with_stubs = with_stubs,
  deep_eq = deep_eq,
  passed = passed,
  failed = failed
}
