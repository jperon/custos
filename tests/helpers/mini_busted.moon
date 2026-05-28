-- tests/helpers/mini_busted.moon
-- Runner Busted minimal en pur Lua : pas de dépendance externe, fonctionne
-- sur LuaJIT seul. Couvre l'API utilisée par les specs de custos
-- (describe/it/before_each/after_each/setup, assert.equals/same/truthy/is_*/
-- has_error/has_no.errors/match/not_equals).

M = {}

-- ── État ─────────────────────────────────────────────────────────────

current_describe = nil  -- pile des describe imbriqués
root_blocks      = {}   -- describe au top level
total            = 0
passed           = 0
failed           = 0
skipped          = 0
failures         = {}   -- {suite, name, err}
running_test     = false

-- ── Comparaison profonde ────────────────────────────────────────────

deep_eq = (a, b) ->
  return true if a == b
  return false unless type(a) == "table" and type(b) == "table"
  ka = 0
  for k, v in pairs a
    ka += 1
    return false unless deep_eq v, b[k]
  kb = 0
  for _ in pairs b
    kb += 1
  ka == kb

-- ── Assertions ──────────────────────────────────────────────────────

fmt = (v) ->
  return string.format("%q", v) if type(v) == "string"
  if type(v) == "table"
    parts = {}
    for k, x in pairs v
      parts[#parts + 1] = tostring(k) .. "=" .. tostring(x)
    return "{" .. table.concat(parts, ", ") .. "}"
  tostring v

fail = (msg, level) ->
  error msg, (level or 1) + 1

A = {}

A.equals = (expected, actual) ->
  if expected != actual
    fail "expected #{fmt expected} but got #{fmt actual}", 2

A.are = { equal: A.equals }

A.same = (expected, actual) ->
  unless deep_eq expected, actual
    fail "expected (deep) #{fmt expected} but got #{fmt actual}", 2

A.not_equals = (expected, actual) ->
  if expected == actual
    fail "expected NOT #{fmt expected} but got it anyway", 2

A.truthy = (v, msg) ->
  unless v
    fail "expected truthy, got #{fmt v} #{msg or ''}", 2

A.is_true       = (v) -> fail "expected true, got #{fmt v}", 2     if v != true
A.is_false      = (v) -> fail "expected false, got #{fmt v}", 2    if v != false
A.is_nil        = (v) -> fail "expected nil, got #{fmt v}", 2      if v != nil
A.is_not_nil    = (v) -> fail "expected non-nil", 2                if v == nil
A.not_nil       = A.is_not_nil
A.falsy         = (v, msg) -> fail "expected falsy, got #{fmt v} #{msg or ''}", 2  if v
A.is_not_true   = (v) -> fail "expected NOT true", 2               if v == true
A.is_not_false  = (v) -> fail "expected NOT false", 2              if v == false
A.is_number     = (v) -> fail "expected number, got #{type v}", 2  if type(v) != "number"
A.is_string     = (v) -> fail "expected string, got #{type v}", 2  if type(v) != "string"
A.is_table      = (v) -> fail "expected table, got #{type v}", 2   if type(v) != "table"
A.is_function   = (v) -> fail "expected function, got #{type v}", 2 if type(v) != "function"

A.match = (pattern, s) ->
  if type(s) != "string" or not s\match pattern
    fail "expected #{fmt s} to match #{fmt pattern}", 2

A.has_error = (fn, expected_msg) ->
  ok, err = pcall fn
  fail "expected fn to raise an error, but it succeeded", 2 if ok
  if expected_msg and not tostring(err)\find expected_msg, 1, true
    fail "expected error to contain #{fmt expected_msg} but got #{fmt err}", 2

A.has_no = {
  errors: (fn) ->
    ok, err = pcall fn
    fail "expected fn to NOT raise, got: #{fmt err}", 2 unless ok
}

-- ── DSL describe/it ─────────────────────────────────────────────────

make_block = (name, parent) -> {
  :name
  :parent
  children:    {}
  tests:       {}
  before_each: {}
  after_each:  {}
  setup:       {}
  teardown:    {}
}

full_name = (block) ->
  parts = {}
  while block
    parts[#parts + 1] = block.name if block.name
    block = block.parent
  -- reverse
  rev = {}
  for i = #parts, 1, -1
    rev[#rev + 1] = parts[i]
  table.concat rev, " "

M.describe = (name, fn) ->
  parent = current_describe
  b = make_block name, parent
  if parent
    parent.children[#parent.children + 1] = b
  else
    root_blocks[#root_blocks + 1] = b
  current_describe = b
  -- pcall : une erreur de chargement à l'intérieur d'un describe ne doit pas
  -- laisser current_describe pollué pour les blocs suivants.
  ok, err = pcall fn
  current_describe = parent
  unless ok
    io.write "  ! describe '#{tostring name}' a échoué au chargement : #{tostring err}\n"

M.it = (name, fn) ->
  unless current_describe
    -- it() au top level : on l'enveloppe dans un describe anonyme,
    -- mais sans laisser current_describe pollué.
    b = make_block nil, nil
    root_blocks[#root_blocks + 1] = b
    b.tests[#b.tests + 1] = { :name, :fn }
    return
  current_describe.tests[#current_describe.tests + 1] = { :name, :fn }

PENDING_TAG = "__mini_busted_pending__:"

M.pending = (name, _fn) ->
  -- Si appelé en dehors d'un it (au niveau describe) : enregistre un test
  -- pending. Si appelé dans un test, lève une erreur spéciale pour marquer
  -- ce test comme pending (compat avec Busted).
  if running_test
    error PENDING_TAG .. tostring(name), 2
  return unless current_describe
  current_describe.tests[#current_describe.tests + 1] = { :name, pending: true }

M._pending_tag = PENDING_TAG

M.before_each = (fn) ->
  current_describe.before_each[#current_describe.before_each + 1] = fn

M.after_each = (fn) ->
  current_describe.after_each[#current_describe.after_each + 1] = fn

M.setup    = (fn) -> current_describe.setup[#current_describe.setup + 1]       = fn
M.teardown = (fn) -> current_describe.teardown[#current_describe.teardown + 1] = fn

-- ── Exécution ───────────────────────────────────────────────────────

collect_hooks = (block, key) ->
  -- hooks en chaîne du root vers le block actuel
  chain = {}
  stack = {}
  b = block
  while b
    stack[#stack + 1] = b
    b = b.parent
  for i = #stack, 1, -1
    for _, h in ipairs stack[i][key]
      chain[#chain + 1] = h
  chain

run_block = (block) ->
  for _, h in ipairs block.setup
    ok, err = pcall h
    print "[setup] ERROR: #{tostring err}" unless ok

  for _, t in ipairs block.tests
    total += 1
    if t.pending
      skipped += 1
      io.write "  ○ #{full_name block} :: #{t.name} (pending)\n"
    else
      for _, h in ipairs collect_hooks block, "before_each"
        pcall h
      running_test = true
      ok, err = pcall t.fn
      running_test = false
      for _, h in ipairs collect_hooks block, "after_each"
        pcall h
      err_str = tostring(err or "")
      pending_pos = err_str\find M._pending_tag, 1, true
      if not ok and pending_pos
        skipped += 1
        reason = err_str\sub pending_pos + #M._pending_tag
        io.write "  ○ #{full_name block} :: #{t.name} (pending: #{reason})\n"
      elseif ok
        passed += 1
        io.write "  ✓ #{full_name block} :: #{t.name}\n"
      else
        failed += 1
        failures[#failures + 1] = {
          name: "#{full_name block} :: #{t.name}"
          err:  tostring err
        }
        io.write "  ✗ #{full_name block} :: #{t.name}\n"
        io.write "    #{tostring err}\n"

  for _, c in ipairs block.children
    run_block c

  for _, h in ipairs block.teardown
    pcall h

-- Isole chaque bloc describe racine : les hooks setup/teardown d'un spec
-- ne polluent pas les tests des specs suivants dans mini.run().
snapshot_loaded = ->
  snap = {}
  for k, v in pairs package.loaded
    snap[k] = v
  snap

restore_loaded = (snap) ->
  for k in pairs package.loaded
    package.loaded[k] = nil if snap[k] == nil
  for k, v in pairs snap
    package.loaded[k] = v

M.run = ->
  baseline = snapshot_loaded!
  for _, b in ipairs root_blocks
    run_block b
    restore_loaded baseline
  io.write "\n──────────────────────────────────────────────\n"
  io.write string.format "Tests: %d  passed: %d  failed: %d  pending: %d\n",
                         total, passed, failed, skipped
  if failed > 0
    io.write "\nÉchecs détaillés :\n"
    for _, f in ipairs failures
      io.write "  ✗ #{f.name}\n    #{f.err}\n"
    return 1
  0

M.reset = ->
  current_describe = nil
  root_blocks      = {}
  total            = 0
  passed           = 0
  failed           = 0
  skipped          = 0
  failures         = {}

-- ── Installation des globales ───────────────────────────────────────

M.install = ->
  _G.describe    = M.describe
  _G.it          = M.it
  _G.pending     = M.pending
  _G.before_each = M.before_each
  _G.after_each  = M.after_each
  _G.setup       = M.setup
  _G.teardown    = M.teardown

  -- assert (sans casser la fonction assert standard de Lua)
  std_assert = assert
  proxy = setmetatable {}, {
    __index: A
    __call:  (_, ...) -> std_assert ...
  }
  _G.assert = proxy

M
