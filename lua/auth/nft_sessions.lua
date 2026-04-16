local ffi = require("ffi")
ffi.cdef([[  typedef struct nft_ctx nft_ctx;
  nft_ctx* nft_ctx_new(unsigned int flags);
  void     nft_ctx_free(nft_ctx *ctx);
  int      nft_run_cmd_from_buffer(nft_ctx *ctx, const char *buf);
]])
local libnft = ffi.load("libnftables.so.1")
local ctx = libnft.nft_ctx_new(0)
if ctx == nil then
  error("nft_ctx_new() failed in auth worker")
end
local NFT_FAMILY, NFT_TABLE
do
  local _obj_0 = require("config")
  NFT_FAMILY, NFT_TABLE = _obj_0.NFT_FAMILY, _obj_0.NFT_TABLE
end
local NFT_SET4 = "authenticated_ips"
local NFT_SET6 = "authenticated_ips6"
local NFT_SET_MAC = "authenticated_macs"
local run_nft
run_nft = function(cmd)
  local rc = libnft.nft_run_cmd_from_buffer(ctx, cmd)
  return rc == 0
end
local add_authenticated4
add_authenticated4 = function(ip, ttl)
  return run_nft("add element " .. tostring(NFT_FAMILY) .. " " .. tostring(NFT_TABLE) .. " " .. tostring(NFT_SET4) .. " { " .. tostring(ip) .. " timeout " .. tostring(ttl) .. "s }")
end
local del_authenticated4
del_authenticated4 = function(ip)
  return run_nft("delete element " .. tostring(NFT_FAMILY) .. " " .. tostring(NFT_TABLE) .. " " .. tostring(NFT_SET4) .. " { " .. tostring(ip) .. " }")
end
local add_authenticated6
add_authenticated6 = function(ip, ttl)
  return run_nft("add element " .. tostring(NFT_FAMILY) .. " " .. tostring(NFT_TABLE) .. " " .. tostring(NFT_SET6) .. " { " .. tostring(ip) .. " timeout " .. tostring(ttl) .. "s }")
end
local del_authenticated6
del_authenticated6 = function(ip)
  return run_nft("delete element " .. tostring(NFT_FAMILY) .. " " .. tostring(NFT_TABLE) .. " " .. tostring(NFT_SET6) .. " { " .. tostring(ip) .. " }")
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
  return run_nft("add element " .. tostring(NFT_FAMILY) .. " " .. tostring(NFT_TABLE) .. " " .. tostring(NFT_SET_MAC) .. " { " .. tostring(mac) .. " timeout " .. tostring(ttl) .. "s }")
end
local del_authenticated_mac
del_authenticated_mac = function(mac)
  return run_nft("delete element " .. tostring(NFT_FAMILY) .. " " .. tostring(NFT_TABLE) .. " " .. tostring(NFT_SET_MAC) .. " { " .. tostring(mac) .. " }")
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
