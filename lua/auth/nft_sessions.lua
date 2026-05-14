local ffi, libnft
do
  local _obj_0 = require("ffi_defs")
  ffi, libnft = _obj_0.ffi, _obj_0.libnft
end
local ctx = libnft.nft_ctx_new(0)
if ctx == nil then
  error("nft_ctx_new() failed in auth worker")
end
local config = require("config")
local NFT_SET4 = "authenticated_ips"
local NFT_SET6 = "authenticated_ips6"
local NFT_SET_MAC = "authenticated_macs"
local run_nft
run_nft = function(cmd)
  local rc = libnft.nft_run_cmd_from_buffer(ctx, cmd)
  return rc == 0
end
local upsert_element
upsert_element = function(set_name, value, ttl)
  local cmd = tostring(config.nft.family) .. " " .. tostring(config.nft.table) .. " " .. tostring(set_name) .. " { " .. tostring(value) .. " timeout " .. tostring(ttl) .. "s }"
  return run_nft("update element " .. tostring(cmd)) or run_nft("add element " .. tostring(cmd))
end
local add_authenticated4
add_authenticated4 = function(ip, ttl)
  return upsert_element(NFT_SET4, ip, ttl)
end
local del_authenticated4
del_authenticated4 = function(ip)
  return run_nft("delete element " .. tostring(config.nft.family) .. " " .. tostring(config.nft.table) .. " " .. tostring(NFT_SET4) .. " { " .. tostring(ip) .. " }")
end
local add_authenticated6
add_authenticated6 = function(ip, ttl)
  return upsert_element(NFT_SET6, ip, ttl)
end
local del_authenticated6
del_authenticated6 = function(ip)
  return run_nft("delete element " .. tostring(config.nft.family) .. " " .. tostring(config.nft.table) .. " " .. tostring(NFT_SET6) .. " { " .. tostring(ip) .. " }")
end
local add_authenticated
add_authenticated = function(ip, ttl)
  if ip:find(":") then
    return add_authenticated6(ip, ttl)
  else
    return add_authenticated4(ip, ttl)
  end
end
local del_authenticated
del_authenticated = function(ip)
  if ip:find(":") then
    return del_authenticated6(ip)
  else
    return del_authenticated4(ip)
  end
end
local add_authenticated_mac
add_authenticated_mac = function(mac, ttl)
  return upsert_element(NFT_SET_MAC, mac, ttl)
end
local del_authenticated_mac
del_authenticated_mac = function(mac)
  return run_nft("delete element " .. tostring(config.nft.family) .. " " .. tostring(config.nft.table) .. " " .. tostring(NFT_SET_MAC) .. " { " .. tostring(mac) .. " }")
end
local cleanup
cleanup = function()
  if ctx ~= nil then
    return libnft.nft_ctx_free(ctx)
  end
end
return {
  add_authenticated4 = add_authenticated4,
  del_authenticated4 = del_authenticated4,
  add_authenticated6 = add_authenticated6,
  del_authenticated6 = del_authenticated6,
  add_authenticated = add_authenticated,
  del_authenticated = del_authenticated,
  add_authenticated_mac = add_authenticated_mac,
  del_authenticated_mac = del_authenticated_mac,
  cleanup = cleanup
}
