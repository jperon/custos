local log_info, log_warn
do
  local _obj_0 = require("log")
  log_info, log_warn = _obj_0.log_info, _obj_0.log_warn
end
local ffi, libc
do
  local _obj_0 = require("ffi_defs")
  ffi, libc = _obj_0.ffi, _obj_0.libc
end
local get_bridge_ifname
get_bridge_ifname = function(auth_cfg)
  if auth_cfg and auth_cfg.bridge_ifname then
    return auth_cfg.bridge_ifname
  end
  local res = io.popen("ip -brief link show type bridge")
  if res then
    local line = res:read("*l")
    res:close()
    if line then
      local name = line:match("^(%S+)")
      if name then
        return name
      else
        local _ = "br"
      end
    end
  end
  return "br"
end
local get_local_cidrs
get_local_cidrs = function(ifname)
  local cidrs = {
    ipv4 = { },
    ipv6 = { }
  }
  local res4 = io.popen("ip -4 route show dev " .. tostring(ifname))
  if res4 then
    for _index_0 = 1, #res4 do
      local line = res4[_index_0]
      local cidr = line:match("([0-9%.]+/[0-9]+)")
      if cidr then
        local mask = cidr:match("/(%d+)$")
        if mask and tonumber(mask) >= 8 then
          table.insert(cidrs.ipv4, cidr)
        end
      end
    end
    res4:close()
  end
  local res6 = io.popen("ip -6 route show dev " .. tostring(ifname))
  if res6 then
    for _index_0 = 1, #res6 do
      local line = res6[_index_0]
      local cidr = line:match("([%x%a%:]+/[0-9]+)")
      if cidr then
        local mask = cidr:match("/(%d+)$")
        if mask and tonumber(mask) >= 48 then
          table.insert(cidrs.ipv6, cidr)
        end
      end
    end
    res6:close()
  end
  return cidrs
end
local inject_localnets
inject_localnets = function(auth_cfg, whitelist)
  if not (auth_cfg and auth_cfg.allow_localnets) then
    return 
  end
  local ifname = get_bridge_ifname(auth_cfg)
  local cidrs = get_local_cidrs(ifname)
  local count = 0
  for _, net in ipairs(cidrs.ipv4) do
    table.insert(whitelist, net)
    count = count + 1
  end
  for _, net in ipairs(cidrs.ipv6) do
    table.insert(whitelist, net)
    count = count + 1
  end
  return log_info({
    action = "localnets_injected",
    bridge = ifname,
    count = count
  })
end
return {
  inject_localnets = inject_localnets,
  get_bridge_ifname = get_bridge_ifname
}
