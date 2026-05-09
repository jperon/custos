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
local nft_compiler = require("filter.nft_compiler")
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
  content = content:gsub("{QUEUE_QUESTIONS}", cfg.nfqueue.questions)
  content = content:gsub("{QUEUE_RESPONSES}", cfg.nfqueue.responses)
  content = content:gsub("{QUEUE_CAPTIVE}", cfg.nfqueue.captive)
  content = content:gsub("{QUEUE_REJECT}", cfg.nfqueue.reject)
  content = content:gsub("{QUEUE_AUTH}", cfg.nfqueue.auth)
  content = content:gsub("{QUEUE_SNI_LOG}", cfg.nfqueue.sni_log)
  content = content:gsub("{NFT_IP_TIMEOUT}", cfg.nft.ip_timeout)
  if get_log_level_num("DEBUG") < get_log_level_num(cfg.runtime.log_level) then
    content = content:gsub("log%s+level%s+debug%s+prefix%s+\"[^\"]*\"", "")
  end
  return content
end
local compile_filter_rules
compile_filter_rules = function(filter_cfg)
  if not (filter_cfg and filter_cfg.rules and #filter_cfg.rules > 0) then
    return ""
  end
  local plan = nft_compiler.compile(filter_cfg)
  return nft_compiler.render(plan)
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
  local cfg = require("config")
  local compiled_rules = compile_filter_rules(cfg.filter)
  if compiled_rules and #compiled_rules > 0 then
    content = content:gsub("(table%s+bridge%s+[%w_%-]+%s*{.-)(%s*}%s*$)", "%1\n" .. compiled_rules .. "%2")
  end
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
