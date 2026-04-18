local bsearch
bsearch = function(arr, n, target)
  local lo, hi = 0, n - 1
  while lo <= hi do
    local mid = math.floor((lo + hi) * 0.5)
    local v = arr[mid]
    if v == target then
      return true
    elseif v < target then
      lo = mid + 1
    else
      hi = mid - 1
    end
  end
  return false
end
return {
  bsearch = bsearch
}
