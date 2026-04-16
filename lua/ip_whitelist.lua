local ffi = require("ffi")
local NFT_FAMILY, NFT_TABLE
do
  local _obj_0 = require("config")
  NFT_FAMILY, NFT_TABLE = _obj_0.NFT_FAMILY, _obj_0.NFT_TABLE
end
ffi.cdef([[  typedef struct nft_ctx nft_ctx;
  nft_ctx* nft_ctx_new(unsigned int flags);
  void     nft_ctx_free(nft_ctx *ctx);
  int      nft_run_cmd_from_buffer(nft_ctx *ctx, const char *buf);
]])
local libnft = ffi.load("libnftables.so.1")
local ctx = libnft.nft_ctx_new(0)
if ctx == nil then
  error("nft_ctx_new() échoué dans ip_whitelist")
end
local SET4 = "ip4_dest_whitelist"
local SET6 = "ip6_dest_whitelist"
local run_nft
run_nft = function(cmd)
  local rc = libnft.nft_run_cmd_from_buffer(ctx, cmd)
  return rc == 0
end
local init
init = function(entries)
  run_nft("flush set " .. tostring(NFT_FAMILY) .. " " .. tostring(NFT_TABLE) .. " " .. tostring(SET4))
  run_nft("flush set " .. tostring(NFT_FAMILY) .. " " .. tostring(NFT_TABLE) .. " " .. tostring(SET6))
  if not entries or #entries == 0 then
    return 
  end
  local v4, v6 = { }, { }
  for _index_0 = 1, #entries do
    local _continue_0 = false
    repeat
      local e = entries[_index_0]
      e = tostring(e):gsub("%s+", "")
      if #e == 0 then
        _continue_0 = true
        break
      end
      if e:find(":") then
        v6[#v6 + 1] = e
      else
        v4[#v4 + 1] = e
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  if #v4 > 0 then
    run_nft("add element " .. tostring(NFT_FAMILY) .. " " .. tostring(NFT_TABLE) .. " " .. tostring(SET4) .. " { " .. tostring(table.concat(v4, ", ")) .. " }")
  end
  if #v6 > 0 then
    return run_nft("add element " .. tostring(NFT_FAMILY) .. " " .. tostring(NFT_TABLE) .. " " .. tostring(SET6) .. " { " .. tostring(table.concat(v6, ", ")) .. " }")
  end
end
local cleanup
cleanup = function()
  if ctx ~= nil then
    return libnft.nft_ctx_free(ctx)
  end
end
return {
  init = init,
  cleanup = cleanup
}
