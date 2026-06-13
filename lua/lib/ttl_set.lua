local new
new = function(max_size, ttl, now_fn)
  if max_size == nil then
    max_size = 4096
  end
  if ttl == nil then
    ttl = 60
  end
  if now_fn == nil then
    now_fn = os.time
  end
  max_size = math.max(1, tonumber(max_size) or 4096)
  ttl = math.max(1, tonumber(ttl) or 60)
  local store = { }
  local size = 0
  local prune
  prune = function()
    local t = now_fn()
    for k, exp in pairs(store) do
      if exp <= t then
        store[k] = nil
        size = size - 1
      end
    end
  end
  local has
  has = function(k)
    if not (k) then
      return false
    end
    local exp = store[k]
    if not (exp) then
      return false
    end
    if exp <= now_fn() then
      store[k] = nil
      size = size - 1
      return false
    end
    return true
  end
  local add
  add = function(k)
    if not (k) then
      return 
    end
    if not (store[k]) then
      if size >= max_size then
        prune()
        if size >= max_size then
          store = { }
          size = 0
        end
      end
      size = size + 1
    end
    store[k] = now_fn() + ttl
  end
  local remove
  remove = function(k)
    if not (k) then
      return 
    end
    if store[k] then
      store[k] = nil
      size = size - 1
    end
  end
  return {
    has = has,
    add = add,
    remove = remove,
    size = function()
      return size
    end
  }
end
return {
  new = new
}
