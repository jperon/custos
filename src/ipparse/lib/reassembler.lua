return function()
  local buf, data = { }, ""
  local next_off, last_off = 0, nil
  return function(self, off, last)
    print(off, last, #self)
    if last_off then
      if last then
        return nil, "duplicate last"
      end
      if off >= last_off then
        return nil, "beyond end"
      end
    end
    if last then
      last_off = off + #self
    end
    if off then
      buf[off] = self
    end
    while true do
      local chunk = buf[next_off]
      if not chunk then
        break
      end
      data = data .. chunk
      buf[next_off] = nil
      next_off = next_off + #chunk
    end
    return next_off == last_off and data
  end
end
