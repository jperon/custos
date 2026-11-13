local coverage = { }
coverage.active = function()
  if _G.__COVERAGE__ == true then
    return true
  end
  if debug.gethook() ~= nil then
    return true
  end
  return false
end
coverage.is_coverage = coverage.active
return coverage
