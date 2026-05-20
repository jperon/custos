-- tests/helpers/mini_busted.lua
-- Runner Busted minimal en pur Lua : pas de dépendance externe, fonctionne
-- sur LuaJIT seul. Couvre l'API utilisée par les specs de custos
-- (describe/it/before_each/after_each/setup, assert.equals/same/truthy/is_*/
-- has_error/has_no.errors/match/not_equals).

local M = {}

-- ── État ─────────────────────────────────────────────────────────────

local current_describe = nil  -- pile des describe imbriqués
local root_blocks = {}        -- describe au top level
local total, passed, failed, skipped = 0, 0, 0, 0
local failures = {}           -- {suite, name, err}
local running_test = false

-- ── Comparaison profonde ────────────────────────────────────────────

local function deep_eq(a, b)
  if a == b then return true end
  if type(a) ~= "table" or type(b) ~= "table" then return false end
  local ka = 0
  for k, v in pairs(a) do
    ka = ka + 1
    if not deep_eq(v, b[k]) then return false end
  end
  local kb = 0
  for _ in pairs(b) do kb = kb + 1 end
  return ka == kb
end

-- ── Assertions ──────────────────────────────────────────────────────

local function fmt(v)
  if type(v) == "string" then return string.format("%q", v) end
  if type(v) == "table" then
    local parts = {}
    for k, x in pairs(v) do parts[#parts+1] = tostring(k).."="..tostring(x) end
    return "{"..table.concat(parts, ", ").."}"
  end
  return tostring(v)
end

local function fail(msg, level)
  error(msg, (level or 1) + 1)
end

local A = {}

function A.equals(expected, actual)
  if expected ~= actual then
    fail("expected "..fmt(expected).." but got "..fmt(actual), 2)
  end
end
A["are"] = { equal = A.equals }

function A.same(expected, actual)
  if not deep_eq(expected, actual) then
    fail("expected (deep) "..fmt(expected).." but got "..fmt(actual), 2)
  end
end

function A.not_equals(expected, actual)
  if expected == actual then
    fail("expected NOT "..fmt(expected).." but got it anyway", 2)
  end
end

function A.truthy(v, msg)
  if not v then fail("expected truthy, got "..fmt(v).." "..(msg or ""), 2) end
end

function A.is_true(v)         if v ~= true        then fail("expected true, got "..fmt(v),         2) end end
function A.is_false(v)        if v ~= false       then fail("expected false, got "..fmt(v),        2) end end
function A.is_nil(v)          if v ~= nil         then fail("expected nil, got "..fmt(v),          2) end end
function A.is_not_nil(v)      if v == nil         then fail("expected non-nil",                    2) end end
function A.is_not_true(v)     if v == true        then fail("expected NOT true",                   2) end end
function A.is_not_false(v)    if v == false       then fail("expected NOT false",                  2) end end
function A.is_number(v)       if type(v)~="number"   then fail("expected number, got "  ..type(v), 2) end end
function A.is_string(v)       if type(v)~="string"   then fail("expected string, got "  ..type(v), 2) end end
function A.is_table(v)        if type(v)~="table"    then fail("expected table, got "   ..type(v), 2) end end
function A.is_function(v)     if type(v)~="function" then fail("expected function, got "..type(v), 2) end end

function A.match(pattern, s)
  if type(s) ~= "string" or not s:match(pattern) then
    fail("expected "..fmt(s).." to match "..fmt(pattern), 2)
  end
end

function A.has_error(fn, expected_msg)
  local ok, err = pcall(fn)
  if ok then fail("expected fn to raise an error, but it succeeded", 2) end
  if expected_msg and not tostring(err):find(expected_msg, 1, true) then
    fail("expected error to contain "..fmt(expected_msg).." but got "..fmt(err), 2)
  end
end

A.has_no = {
  errors = function(fn)
    local ok, err = pcall(fn)
    if not ok then fail("expected fn to NOT raise, got: "..fmt(err), 2) end
  end,
}

-- ── DSL describe/it ─────────────────────────────────────────────────

local function make_block(name, parent)
  return {
    name = name,
    parent = parent,
    children = {},
    tests = {},
    before_each = {},
    after_each = {},
    setup = {},
    teardown = {},
  }
end

local function full_name(block)
  local parts = {}
  while block do
    if block.name then parts[#parts+1] = block.name end
    block = block.parent
  end
  -- reverse
  local rev = {}
  for i = #parts, 1, -1 do rev[#rev+1] = parts[i] end
  return table.concat(rev, " ")
end

function M.describe(name, fn)
  local parent = current_describe
  local b = make_block(name, parent)
  if parent then
    parent.children[#parent.children+1] = b
  else
    root_blocks[#root_blocks+1] = b
  end
  current_describe = b
  -- pcall : une erreur de chargement à l'intérieur d'un describe ne doit pas
  -- laisser current_describe pollué pour les blocs suivants.
  local ok, err = pcall(fn)
  current_describe = parent
  if not ok then
    io.write("  ! describe '"..tostring(name).."' a échoué au chargement : "..tostring(err).."\n")
  end
end

function M.it(name, fn)
  if not current_describe then
    -- it() au top level : on l'enveloppe dans un describe anonyme,
    -- mais sans laisser current_describe pollué.
    local b = make_block(nil, nil)
    root_blocks[#root_blocks+1] = b
    b.tests[#b.tests+1] = { name = name, fn = fn }
    return
  end
  current_describe.tests[#current_describe.tests+1] = { name = name, fn = fn }
end

local PENDING_TAG = "__mini_busted_pending__:"

function M.pending(name, _fn)
  -- Si appelé en dehors d'un it (au niveau describe) : enregistre un test
  -- pending. Si appelé dans un test, lève une erreur spéciale pour marquer
  -- ce test comme pending (compat avec Busted).
  if running_test then
    error(PENDING_TAG..tostring(name), 2)
  end
  if not current_describe then return end
  current_describe.tests[#current_describe.tests+1] = { name = name, pending = true }
end

M._pending_tag = PENDING_TAG

function M.before_each(fn)
  current_describe.before_each[#current_describe.before_each+1] = fn
end

function M.after_each(fn)
  current_describe.after_each[#current_describe.after_each+1] = fn
end

function M.setup(fn)        current_describe.setup[#current_describe.setup+1]     = fn end
function M.teardown(fn)     current_describe.teardown[#current_describe.teardown+1] = fn end

-- ── Exécution ───────────────────────────────────────────────────────

local function collect_hooks(block, key)
  -- hooks en chaîne du root vers le block actuel
  local chain = {}
  local stack = {}
  local b = block
  while b do
    stack[#stack+1] = b
    b = b.parent
  end
  for i = #stack, 1, -1 do
    for _, h in ipairs(stack[i][key]) do chain[#chain+1] = h end
  end
  return chain
end

local function run_block(block)
  for _, h in ipairs(block.setup) do
    local ok, err = pcall(h)
    if not ok then print("[setup] ERROR: "..tostring(err)) end
  end

  for _, t in ipairs(block.tests) do
    total = total + 1
    if t.pending then
      skipped = skipped + 1
      io.write("  ○ "..full_name(block).." :: "..t.name.." (pending)\n")
    else
      for _, h in ipairs(collect_hooks(block, "before_each")) do pcall(h) end
      running_test = true
      local ok, err = pcall(t.fn)
      running_test = false
      for _, h in ipairs(collect_hooks(block, "after_each")) do pcall(h) end
      local err_str = tostring(err or "")
      local pending_pos = err_str:find(M._pending_tag, 1, true)
      if not ok and pending_pos then
        skipped = skipped + 1
        local reason = err_str:sub(pending_pos + #M._pending_tag)
        io.write("  ○ "..full_name(block).." :: "..t.name.." (pending: "..reason..")\n")
      elseif ok then
        passed = passed + 1
        io.write("  ✓ "..full_name(block).." :: "..t.name.."\n")
      else
        failed = failed + 1
        failures[#failures+1] = {
          name = full_name(block).." :: "..t.name,
          err  = tostring(err),
        }
        io.write("  ✗ "..full_name(block).." :: "..t.name.."\n")
        io.write("    "..tostring(err).."\n")
      end
    end
  end

  for _, c in ipairs(block.children) do run_block(c) end

  for _, h in ipairs(block.teardown) do pcall(h) end
end

function M.run()
  for _, b in ipairs(root_blocks) do run_block(b) end
  io.write("\n──────────────────────────────────────────────\n")
  io.write(string.format("Tests: %d  passed: %d  failed: %d  pending: %d\n",
                         total, passed, failed, skipped))
  if failed > 0 then
    io.write("\nÉchecs détaillés :\n")
    for _, f in ipairs(failures) do
      io.write("  ✗ "..f.name.."\n    "..f.err.."\n")
    end
    return 1
  end
  return 0
end

function M.reset()
  current_describe = nil
  root_blocks = {}
  total, passed, failed, skipped = 0, 0, 0, 0
  failures = {}
end

-- ── Installation des globales ───────────────────────────────────────

function M.install()
  _G.describe    = M.describe
  _G.it          = M.it
  _G.pending     = M.pending
  _G.before_each = M.before_each
  _G.after_each  = M.after_each
  _G.setup       = M.setup
  _G.teardown    = M.teardown

  -- assert (sans casser la fonction assert standard de Lua)
  local std_assert = assert
  local proxy = setmetatable({}, {
    __index = A,
    __call  = function(_, ...) return std_assert(...) end,
  })
  _G.assert = proxy
end

return M
