local run = require("bench.run")
return run.main((function()
  local _accum_0 = { }
  local _len_0 = 1
  local _list_0 = arg
  for _index_0 = 1, #_list_0 do
    local a = _list_0[_index_0]
    _accum_0[_len_0] = a
    _len_0 = _len_0 + 1
  end
  return _accum_0
end)())
