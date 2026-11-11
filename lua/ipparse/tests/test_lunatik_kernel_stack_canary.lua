local REQUIRED_DEPTH = 2
local MAX_PROBE = 12
local ENTRY_MODULES = {
  "ipparse",
  "ipparse.fun",
  "ipparse.fun.tables",
  "ipparse.fun.memo",
  "ipparse.fun.iter",
  "ipparse.fun.protected",
  "ipparse.l2.ethernet",
  "ipparse.l3.ip",
  "ipparse.l3.ip4",
  "ipparse.l3.ip6",
  "ipparse.l3.fragmented_ip4",
  "ipparse.l4.tcp",
  "ipparse.l4.udp",
  "ipparse.l4.tcp_stream",
  "ipparse.l4.quic",
  "ipparse.l4.quic.frames",
  "ipparse.l7.dns",
  "ipparse.l7.tls",
  "ipparse.l7.tls.handshake",
  "ipparse.l7.tls.handshake.client_hello",
  "ipparse.l7.quic",
  "ipparse.l7.quic.session",
  "ipparse.lib.hkdf",
  "ipparse.lib.crypto.backend.lunatik"
}
local pass = 0
local total = 0
local id = 0
local unload_ipparse
unload_ipparse = function()
  local keys = { }
  for k in pairs(package.loaded) do
    if type(k) == "string" and (k == "ipparse" or k:sub(1, 8) == "ipparse.") then
      keys[#keys + 1] = k
    end
  end
  for i = 1, #keys do
    package.loaded[keys[i]] = nil
  end
end
local make_loader
make_loader = function(next_name)
  return function()
    require(next_name)
    return true
  end
end
local probe
probe = function(mod, depth)
  id = id + 1
  local names = { }
  for k = 1, depth do
    names[k] = "ipparse_canary." .. tostring(id) .. "." .. tostring(k)
  end
  local first = mod
  if depth > 0 then
    first = names[1]
    for k = 1, depth do
      local next_name = mod
      if k < depth then
        next_name = names[k + 1]
      end
      package.preload[names[k]] = make_loader(next_name)
    end
  end
  unload_ipparse()
  local ok, err = pcall(require, first)
  for k = 1, depth do
    package.preload[names[k]] = nil
    package.loaded[names[k]] = nil
  end
  unload_ipparse()
  return ok, err
end
local is_stack_error
is_stack_error = function(err)
  local s = tostring(err)
  if s:find("stack overflow", 1, true) then
    return true
  end
  if s:find("error in error handling", 1, true) then
    return true
  end
  return false
end
local min_max = nil
local truncate
truncate = function(err)
  local msg = (tostring(err)):gsub("%s+", " ")
  return msg:sub(1, 120)
end
local HEAVY_FUN = {
  "ipparse.fun",
  "ipparse.fun.iter",
  "ipparse.fun.memo",
  "ipparse.fun.protected"
}
local BASE_EXEMPT = {
  ["ipparse"] = true,
  ["ipparse.fun"] = true,
  ["ipparse.fun.tables"] = true,
  ["ipparse.fun.memo"] = true,
  ["ipparse.fun.iter"] = true,
  ["ipparse.fun.protected"] = true,
  ["ipparse.lib.hkdf"] = true,
  ["ipparse.lib.crypto.backend.lunatik"] = true
}
local FUN_EXEMPT = {
  ["ipparse.fun"] = true,
  ["ipparse.fun.tables"] = true,
  ["ipparse.fun.memo"] = true,
  ["ipparse.fun.iter"] = true,
  ["ipparse.fun.protected"] = true
}
local REQUIRED_DEPTH_OVERRIDES = {
  ["ipparse.fun"] = 0,
  ["ipparse.fun.iter"] = 0,
  ["ipparse.fun.protected"] = 0,
  ["ipparse.fun.memo"] = 0
}
for i = 1, #ENTRY_MODULES do
  local mod = ENTRY_MODULES[i]
  local max_depth = 0
  local skipped = false
  local skip_err = nil
  local first_err = nil
  local first_fail_depth = nil
  local ok0, err0 = probe(mod, 0)
  if not ok0 then
    first_err = err0
    first_fail_depth = 0
    if is_stack_error(err0) then
      max_depth = 0
    else
      skipped = true
      skip_err = err0
    end
  end
  if not skipped then
    for d = 1, MAX_PROBE do
      local ok, err = probe(mod, d)
      if ok then
        max_depth = d
      else
        if first_err == nil then
          first_err = err
          first_fail_depth = d
        end
        break
      end
    end
  end
  local base_err = nil
  local exempt_base = BASE_EXEMPT[mod] or false
  local exempt_fun = FUN_EXEMPT[mod] or false
  unload_ipparse()
  local ok_mod, err_mod = pcall(require, mod)
  if not ok_mod then
    base_err = "reload failed: " .. tostring(truncate(err_mod))
  else
    if not exempt_base and package.loaded["ipparse"] == nil then
      base_err = "did not load ipparse first"
    end
    if not exempt_fun then
      for k = 1, #HEAVY_FUN do
        if package.loaded[HEAVY_FUN[k]] ~= nil then
          base_err = "pulled in " .. tostring(HEAVY_FUN[k])
          break
        end
      end
    end
  end
  unload_ipparse()
  if first_err ~= nil then
    local stop_kind = is_stack_error(first_err) and "stack" or "other"
    print("CANARY\t" .. tostring(mod) .. "\tmax_depth=" .. tostring(max_depth) .. "\tstop=" .. tostring(stop_kind) .. "\t" .. tostring(truncate(first_err)))
  elseif max_depth >= MAX_PROBE then
    print("CANARY\t" .. tostring(mod) .. "\tmax_depth>=" .. tostring(MAX_PROBE))
  else
    print("CANARY\t" .. tostring(mod) .. "\tmax_depth=" .. tostring(max_depth))
  end
  if skipped then
    print("SKIP\t" .. tostring(mod) .. "\t" .. tostring(skip_err))
  else
    total = total + 1
    local required_depth = REQUIRED_DEPTH_OVERRIDES[mod]
    if required_depth == nil then
      required_depth = REQUIRED_DEPTH
    end
    local non_stack_fail = first_err ~= nil and first_fail_depth >= 1 and not is_stack_error(first_err)
    if base_err ~= nil then
      print("FAIL\tstack canary: " .. tostring(mod) .. " " .. tostring(base_err))
    elseif non_stack_fail then
      print("FAIL\tstack canary: " .. tostring(mod) .. " failed at depth " .. tostring(first_fail_depth) .. " with a non-stack error: " .. tostring(first_err))
    elseif max_depth >= required_depth then
      pass = pass + 1
      print("PASS\tstack canary: " .. tostring(mod) .. " loads from depth " .. tostring(max_depth))
    else
      print("FAIL\tstack canary: " .. tostring(mod) .. " loads from depth " .. tostring(max_depth) .. " only (need " .. tostring(required_depth) .. ")")
    end
    if min_max == nil or max_depth < min_max then
      min_max = max_depth
    end
  end
end
if min_max == nil then
  min_max = 0
end
print("==> Stack canary: " .. tostring(pass) .. "/" .. tostring(total) .. ", min max_depth=" .. tostring(min_max))
return unload_ipparse()
