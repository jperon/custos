local M = { }
local current_describe = nil
local root_blocks = { }
local total = 0
local passed = 0
local failed = 0
local skipped = 0
local failures = { }
local running_test = false
local deep_eq
deep_eq = function(a, b)
  if a == b then
    return true
  end
  if not (type(a) == "table" and type(b) == "table") then
    return false
  end
  local ka = 0
  for k, v in pairs(a) do
    ka = ka + 1
    if not (deep_eq(v, b[k])) then
      return false
    end
  end
  local kb = 0
  for _ in pairs(b) do
    kb = kb + 1
  end
  return ka == kb
end
local fmt
fmt = function(v)
  if type(v) == "string" then
    return string.format("%q", v)
  end
  if type(v) == "table" then
    local parts = { }
    for k, x in pairs(v) do
      parts[#parts + 1] = tostring(k) .. "=" .. tostring(x)
    end
    return "{" .. table.concat(parts, ", ") .. "}"
  end
  return tostring(v)
end
local fail
fail = function(msg, level)
  return error(msg, (level or 1) + 1)
end
local A = { }
A.equals = function(expected, actual)
  if expected ~= actual then
    return fail("expected " .. tostring(fmt(expected)) .. " but got " .. tostring(fmt(actual)), 2)
  end
end
A.are = {
  equal = A.equals
}
A.same = function(expected, actual)
  if not (deep_eq(expected, actual)) then
    return fail("expected (deep) " .. tostring(fmt(expected)) .. " but got " .. tostring(fmt(actual)), 2)
  end
end
A.not_equals = function(expected, actual)
  if expected == actual then
    return fail("expected NOT " .. tostring(fmt(expected)) .. " but got it anyway", 2)
  end
end
A.truthy = function(v, msg)
  if not (v) then
    return fail("expected truthy, got " .. tostring(fmt(v)) .. " " .. tostring(msg or ''), 2)
  end
end
A.is_true = function(v)
  if v ~= true then
    return fail("expected true, got " .. tostring(fmt(v)), 2)
  end
end
A.is_false = function(v)
  if v ~= false then
    return fail("expected false, got " .. tostring(fmt(v)), 2)
  end
end
A.is_nil = function(v)
  if v ~= nil then
    return fail("expected nil, got " .. tostring(fmt(v)), 2)
  end
end
A.is_not_nil = function(v)
  if v == nil then
    return fail("expected non-nil", 2)
  end
end
A.is_not_true = function(v)
  if v == true then
    return fail("expected NOT true", 2)
  end
end
A.is_not_false = function(v)
  if v == false then
    return fail("expected NOT false", 2)
  end
end
A.is_number = function(v)
  if type(v) ~= "number" then
    return fail("expected number, got " .. tostring(type(v)), 2)
  end
end
A.is_string = function(v)
  if type(v) ~= "string" then
    return fail("expected string, got " .. tostring(type(v)), 2)
  end
end
A.is_table = function(v)
  if type(v) ~= "table" then
    return fail("expected table, got " .. tostring(type(v)), 2)
  end
end
A.is_function = function(v)
  if type(v) ~= "function" then
    return fail("expected function, got " .. tostring(type(v)), 2)
  end
end
A.match = function(pattern, s)
  if type(s) ~= "string" or not s:match(pattern) then
    return fail("expected " .. tostring(fmt(s)) .. " to match " .. tostring(fmt(pattern)), 2)
  end
end
A.has_error = function(fn, expected_msg)
  local ok, err = pcall(fn)
  if ok then
    fail("expected fn to raise an error, but it succeeded", 2)
  end
  if expected_msg and not tostring(err):find(expected_msg, 1, true) then
    return fail("expected error to contain " .. tostring(fmt(expected_msg)) .. " but got " .. tostring(fmt(err)), 2)
  end
end
A.has_no = {
  errors = function(fn)
    local ok, err = pcall(fn)
    if not (ok) then
      return fail("expected fn to NOT raise, got: " .. tostring(fmt(err)), 2)
    end
  end
}
local make_block
make_block = function(name, parent)
  return {
    name = name,
    parent = parent,
    children = { },
    tests = { },
    before_each = { },
    after_each = { },
    setup = { },
    teardown = { }
  }
end
local full_name
full_name = function(block)
  local parts = { }
  while block do
    if block.name then
      parts[#parts + 1] = block.name
    end
    block = block.parent
  end
  local rev = { }
  for i = #parts, 1, -1 do
    rev[#rev + 1] = parts[i]
  end
  return table.concat(rev, " ")
end
M.describe = function(name, fn)
  local parent = current_describe
  local b = make_block(name, parent)
  if parent then
    parent.children[#parent.children + 1] = b
  else
    root_blocks[#root_blocks + 1] = b
  end
  current_describe = b
  local ok, err = pcall(fn)
  current_describe = parent
  if not (ok) then
    return io.write("  ! describe '" .. tostring(tostring(name)) .. "' a échoué au chargement : " .. tostring(tostring(err)) .. "\n")
  end
end
M.it = function(name, fn)
  if not (current_describe) then
    local b = make_block(nil, nil)
    root_blocks[#root_blocks + 1] = b
    b.tests[#b.tests + 1] = {
      name = name,
      fn = fn
    }
    return 
  end
  current_describe.tests[#current_describe.tests + 1] = {
    name = name,
    fn = fn
  }
end
local PENDING_TAG = "__mini_busted_pending__:"
M.pending = function(name, _fn)
  if running_test then
    error(PENDING_TAG .. tostring(name), 2)
  end
  if not (current_describe) then
    return 
  end
  current_describe.tests[#current_describe.tests + 1] = {
    name = name,
    pending = true
  }
end
M._pending_tag = PENDING_TAG
M.before_each = function(fn)
  current_describe.before_each[#current_describe.before_each + 1] = fn
end
M.after_each = function(fn)
  current_describe.after_each[#current_describe.after_each + 1] = fn
end
M.setup = function(fn)
  current_describe.setup[#current_describe.setup + 1] = fn
end
M.teardown = function(fn)
  current_describe.teardown[#current_describe.teardown + 1] = fn
end
local collect_hooks
collect_hooks = function(block, key)
  local chain = { }
  local stack = { }
  local b = block
  while b do
    stack[#stack + 1] = b
    b = b.parent
  end
  for i = #stack, 1, -1 do
    for _, h in ipairs(stack[i][key]) do
      chain[#chain + 1] = h
    end
  end
  return chain
end
local run_block
run_block = function(block)
  for _, h in ipairs(block.setup) do
    local ok, err = pcall(h)
    if not (ok) then
      print("[setup] ERROR: " .. tostring(tostring(err)))
    end
  end
  for _, t in ipairs(block.tests) do
    total = total + 1
    if t.pending then
      skipped = skipped + 1
      io.write("  ○ " .. tostring(full_name(block)) .. " :: " .. tostring(t.name) .. " (pending)\n")
    else
      for _, h in ipairs(collect_hooks(block, "before_each")) do
        pcall(h)
      end
      running_test = true
      local ok, err = pcall(t.fn)
      running_test = false
      for _, h in ipairs(collect_hooks(block, "after_each")) do
        pcall(h)
      end
      local err_str = tostring(err or "")
      local pending_pos = err_str:find(M._pending_tag, 1, true)
      if not ok and pending_pos then
        skipped = skipped + 1
        local reason = err_str:sub(pending_pos + #M._pending_tag)
        io.write("  ○ " .. tostring(full_name(block)) .. " :: " .. tostring(t.name) .. " (pending: " .. tostring(reason) .. ")\n")
      elseif ok then
        passed = passed + 1
        io.write("  ✓ " .. tostring(full_name(block)) .. " :: " .. tostring(t.name) .. "\n")
      else
        failed = failed + 1
        failures[#failures + 1] = {
          name = tostring(full_name(block)) .. " :: " .. tostring(t.name),
          err = tostring(err)
        }
        io.write("  ✗ " .. tostring(full_name(block)) .. " :: " .. tostring(t.name) .. "\n")
        io.write("    " .. tostring(tostring(err)) .. "\n")
      end
    end
  end
  for _, c in ipairs(block.children) do
    run_block(c)
  end
  for _, h in ipairs(block.teardown) do
    pcall(h)
  end
end
local snapshot_loaded
snapshot_loaded = function()
  local snap = { }
  for k, v in pairs(package.loaded) do
    snap[k] = v
  end
  return snap
end
local restore_loaded
restore_loaded = function(snap)
  for k in pairs(package.loaded) do
    if snap[k] == nil then
      package.loaded[k] = nil
    end
  end
  for k, v in pairs(snap) do
    package.loaded[k] = v
  end
end
M.run = function()
  local baseline = snapshot_loaded()
  for _, b in ipairs(root_blocks) do
    run_block(b)
    restore_loaded(baseline)
  end
  io.write("\n──────────────────────────────────────────────\n")
  io.write(string.format("Tests: %d  passed: %d  failed: %d  pending: %d\n", total, passed, failed, skipped))
  if failed > 0 then
    io.write("\nÉchecs détaillés :\n")
    for _, f in ipairs(failures) do
      io.write("  ✗ " .. tostring(f.name) .. "\n    " .. tostring(f.err) .. "\n")
    end
    return 1
  end
  return 0
end
M.reset = function()
  current_describe = nil
  root_blocks = { }
  total = 0
  passed = 0
  failed = 0
  skipped = 0
  failures = { }
end
M.install = function()
  _G.describe = M.describe
  _G.it = M.it
  _G.pending = M.pending
  _G.before_each = M.before_each
  _G.after_each = M.after_each
  _G.setup = M.setup
  _G.teardown = M.teardown
  local std_assert = assert
  local proxy = setmetatable({ }, {
    __index = A,
    __call = function(_, ...)
      return std_assert(...)
    end
  })
  _G.assert = proxy
end
return M
