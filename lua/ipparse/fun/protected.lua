local M = { }
local xpcall_passes_args = select(2, xpcall((function(x)
  return x
end), (function()
  return true
end), true)) == true
M.protected = function(fn, op)
  local leak_debug = M.leak_debug
  local onerror
  onerror = function(err)
    print(err)
    if leak_debug then
      print(debug.traceback())
    end
    if op then
      return op()
    end
  end
  if xpcall_passes_args then
    return function(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z)
      local ok
      ok, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z = xpcall(fn, onerror, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z)
      if ok then
        return a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z
      end
    end
  else
    return function(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z)
      local call
      call = function()
        return fn(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z)
      end
      local ok
      ok, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z = xpcall(call, onerror)
      if ok then
        return a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z
      end
    end
  end
end
return M
