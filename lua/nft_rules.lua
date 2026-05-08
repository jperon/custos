local ffi, libnft
do
  local _obj_0 = require("ffi_defs")
  ffi, libnft = _obj_0.ffi, _obj_0.libnft
end
local log_info, log_warn, get_log_level_num
do
  local _obj_0 = require("log")
  log_info, log_warn, get_log_level_num = _obj_0.log_info, _obj_0.log_warn, _obj_0.get_log_level_num
end
local ctx = libnft.nft_ctx_new(0)
if ctx == nil then
  error("nft_rules: nft_ctx_new() failed")
end
local nft_file_path
nft_file_path = function()
  local src = debug.getinfo(1, "S").source
  local dir = src:match("^@(.*/)") or "./"
  return dir .. "dns-filter-bridge.nft"
end
local substitute
substitute = function(content)
  local cfg = require("config")
  content = content:gsub("{QUEUE_QUESTIONS}", cfg.QUEUE_QUESTIONS)
  content = content:gsub("{QUEUE_RESPONSES}", cfg.QUEUE_RESPONSES)
  content = content:gsub("{QUEUE_CAPTIVE}", cfg.QUEUE_CAPTIVE)
  content = content:gsub("{QUEUE_REJECT}", cfg.QUEUE_REJECT)
  content = content:gsub("{QUEUE_AUTH}", cfg.QUEUE_AUTH)
  content = content:gsub("{QUEUE_SNI_LOG}", cfg.QUEUE_SNI_LOG)
  content = content:gsub("{NFT_IP_TIMEOUT}", cfg.NFT_IP_TIMEOUT)
  if get_log_level_num("DEBUG") < get_log_level_num(cfg.LOG_LEVEL) then
    content = content:gsub("log%s+level%s+debug%s+prefix%s+\"[^\"]*\"", "")
  end
  return content
end
local apply
apply = function()
  local path = nft_file_path()
  local fh, err = io.open(path, "r")
  if not (fh) then
    log_warn({
      action = "nft_rules_file_missing",
      path = path,
      err = err
    })
    return false
  end
  local content = fh:read("*a")
  fh:close()
  content = substitute(content)
  local tmpfile = "/tmp/custos-rules.nft"
  local tmpfh, tmp_err = io.open(tmpfile, "w")
  if not (tmpfh) then
    log_warn({
      action = "nft_rules_tempfile_failed",
      path = tmpfile,
      err = tmp_err
    })
    return false
  end
  tmpfh:write(content)
  tmpfh:close()
  local rc = os.execute("nft -f " .. tostring(tmpfile) .. " 2>/dev/null")
  if rc ~= 0 then
    log_warn({
      action = "nft_rules_apply_failed",
      path = path
    })
    return false
  end
  log_info({
    action = "nft_rules_applied",
    path = path
  })
  return true
end
return {
  apply = apply
}
