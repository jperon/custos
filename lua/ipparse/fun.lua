local bidirectional, zero_indexed, opairs
do
  local _obj_0 = require("ipparse.fun.tables")
  bidirectional, zero_indexed, opairs = _obj_0.bidirectional, _obj_0.zero_indexed, _obj_0.opairs
end
local memo, memoN
do
  local _obj_0 = require("ipparse.fun.memo")
  memo, memoN = _obj_0.memo, _obj_0.memoN
end
local iter, wrap, generate, range
do
  local _obj_0 = require("ipparse.fun.iter")
  iter, wrap, generate, range = _obj_0.iter, _obj_0.wrap, _obj_0.generate, _obj_0.range
end
local protected_mod = require("ipparse.fun.protected")
local protected
protected = protected_mod.protected
local _ = {
  bidirectional = bidirectional,
  memo = memo,
  memoN = memoN,
  iter = iter,
  wrap = wrap,
  range = range,
  opairs = opairs,
  generate = generate,
  zero_indexed = zero_indexed,
  protected = protected,
  __index = function(_, k)
    if k == "leak_debug" then
      return protected_mod.leak_debug
    end
    local fn
    fn = function(self, ...)
      local o = (type(self) == 'table' and iter or wrap)(self)
      return o[k](o, ...)
    end
    rawset(_, k, fn)
    return fn
  end,
  __newindex = function(_, k, v)
    if k == "leak_debug" then
      protected_mod.leak_debug = v
    else
      return rawset(_, k, v)
    end
  end
}
return setmetatable(_, _)
