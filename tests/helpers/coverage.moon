-- tests/helpers/coverage.moon
-- Détection d'un run sous couverture (luacov / line_coverage_* / quick_coverage).
-- Utilisé pour sauter les assertions d'allocation ou de temps, que le hook de
-- couverture fausse (il alloue et ralentit chaque ligne instrumentée).

coverage = {}

coverage.active = ->
  if _G.__COVERAGE__ == true
    return true
  if debug.gethook() ~= nil
    return true
  false

coverage.is_coverage = coverage.active

return coverage
