-- tests/test_framework.moon
-- Mini framework de test unitaire consolidé pour CustosVirginum.
-- Usage:
--   tf = require "test_framework"
--   tf.test("nom", -> ...assertions...)
--   tf.run_suite!("Nom de suite", tests)
--
-- Le framework est autocontenu : pas de dépendance externe.

export passed, failed
passed, failed = 0, 0
export current_suite

current_suite = nil

-- ── Comparaison profonde ──────────────────────────────────────────

deep_eq = (a, b) ->
  ta, tb = type(a), type(b)
  return false unless ta == tb

  if ta == "table"
    -- compter les clés
    ka, kb = 0, 0
    for _ in pairs(a) do ka += 1
    for _ in pairs(b) do kb += 1
    return false unless ka == kb

    for k, v in pairs(a)
      return false unless deep_eq(v, b[k])
    return true

  a == b

-- ── Assertions ────────────────────────────────────────────────────

assert_eq = (got, expected, msg) ->
  unless deep_eq(got, expected)
    error "#{msg or "assertion échouée"}\n       got:      #{tostring(got)}\n       expected: #{tostring(expected)}", 2

assert_ne = (got, unexpected, msg) ->
  if deep_eq(got, unexpected)
    error "#{msg or "assertion échouée"}\n       got:      #{tostring(got)}\n       unexpected: #{tostring(unexpected)}", 2

assert_true = (v, msg) ->
  unless v
    error "#{msg or "expected true"}\n       got: #{tostring(v)}", 2

assert_false = (v, msg) ->
  if v
    error "#{msg or "expected false"}\n       got: #{tostring(v)}", 2

assert_nil = (v, msg) ->
  unless v == nil
    error "#{msg or "expected nil"}\n       got: #{tostring(v)}", 2

assert_not_nil = (v, msg) ->
  if v == nil
    error "#{msg or "expected non-nil"}\n       got: nil", 2

assert_contains = (haystack, needle, msg) ->
  unless haystack and tostring(haystack)\find(tostring(needle), 1, true)
    error "#{msg or "missing substring"}\n       needle: #{tostring(needle)}\n       haystack: #{tostring(haystack)}", 2

assert_matches = (haystack, pattern, msg) ->
  unless haystack and tostring(haystack)\match(pattern)
    error "#{msg or "no match"}\n       pattern: #{pattern}\n       haystack: #{tostring(haystack)}", 2

assert_throws = (pattern, fn) ->
  ok, err = pcall fn
  if ok
    error "expected error matching '#{pattern}', but no error was raised", 2
  unless err and tostring(err)\find(pattern, 1, true)
    error "expected error matching '#{pattern}', got: #{tostring(err)}", 2

-- ── Stubbing ──────────────────────────────────────────────────────

-- Sauvegarde la table originale de package.loaded[name] et la remplace par mock.
-- Retourne une fonction de restauration.
stub_module = (name, mock) ->
  orig = package.loaded[name]
  package.loaded[name] = mock
  -> package.loaded[name] = orig

-- Exécute fn avec les modules stubbés, puis restaure tout.
with_stubs = (stubs, fn) ->
  restore_fns = {}
  for name, mock in pairs(stubs)
    table.insert restore_fns, stub_module(name, mock)
  ok, err = pcall fn
  for r in *restore_fns
    r!
  unless ok
    error err, 2

-- ── Test runner ─────────────────────────────────────────────────────

-- Exécute un test individuel et met à jour passed/failed.
test = (name, fn) ->
  ok, err = pcall fn
  if ok
    passed += 1
    if current_suite
      io.write "      ✓ #{name}\n"
    else
      io.write "  ✓ #{name}\n"
  else
    failed += 1
    if current_suite
      io.write "      ✗ #{name}\n         #{tostring(err)\gsub("\n", "\n         ")}\n"
    else
      io.write "  ✗ #{name}\n     #{tostring(err)\gsub("\n", "\n     ")}\n"

-- Exécute une suite : une table { {name, fn}, ... }.
run_suite = (suite_name, tests) ->
  old_suite = current_suite
  current_suite = suite_name
  io.write "\n━━━ #{suite_name} ━━━\n"
  local suite_passed, suite_failed
  suite_passed, suite_failed = 0, 0
  for t in *tests
    before_passed, before_failed = passed, failed
    test t[1], t[2]
    suite_passed += passed - before_passed
    suite_failed += failed - before_failed
  current_suite = old_suite
  io.write "  #{suite_passed} passé(s), #{suite_failed} échec(s)\n"
  { passed: suite_passed, failed: suite_failed }

-- Imprime le résumé global.
summary = ->
  io.write "\n"
  io.write "══════════════════════════════════════════════════\n"
  if failed == 0
    io.write "  ✅ Tous les tests passés : #{passed} test(s)\n"
  else
    io.write "  ⚠️  #{passed} passé(s), #{failed} échec(s)\n"
  io.write "══════════════════════════════════════════════════\n"
  io.write "\n"

-- Reset compteurs (utile entre plusieurs fichiers de test).
reset = ->
  passed, failed = 0, 0

{
  :test
  :run_suite
  :summary
  :reset
  :assert_eq
  :assert_ne
  :assert_true
  :assert_false
  :assert_nil
  :assert_not_nil
  :assert_contains
  :assert_matches
  :assert_throws
  :stub_module
  :with_stubs
  :deep_eq
  :passed
  :failed
}
