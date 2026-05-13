local ffi, libnft
do
  local _obj_0 = require("ffi_defs")
  ffi, libnft = _obj_0.ffi, _obj_0.libnft
end
local log_info, log_warn, log_debug, get_log_level_num
do
  local _obj_0 = require("log")
  log_info, log_warn, log_debug, get_log_level_num = _obj_0.log_info, _obj_0.log_warn, _obj_0.log_debug, _obj_0.get_log_level_num
end
local nft_compiler = require("filter.nft_compiler")
local nft_dynamic_sets = require("filter.nft_dynamic_sets")
local rule = require("filter.rule")
local ctx = libnft.nft_ctx_new(0)
if ctx == nil then
  error("nft_rules: nft_ctx_new() failed")
end
local get_error_buffer
get_error_buffer = function()
  if not (ctx) then
    return nil
  end
  local ok, ptr = pcall(function()
    return libnft.nft_ctx_get_error_buffer(ctx)
  end)
  if not (ok and ptr ~= nil) then
    return nil
  end
  local msg = ffi.string(ptr)
  if msg and msg ~= "" then
    return msg
  end
end
local run_cmd
run_cmd = function(cmd, opts)
  if opts == nil then
    opts = nil
  end
  local rc = libnft.nft_run_cmd_from_buffer(ctx, cmd)
  if rc ~= 0 then
    local nft_err = get_error_buffer()
    if not (opts and opts.quiet) then
      log_warn({
        action = "nft_cmd_failed",
        cmd = cmd,
        rc = rc,
        nft_err = nft_err or ""
      })
    end
    return false, nft_err
  end
  return true, nil
end
local nft_file_path
nft_file_path = function()
  local src = debug.getinfo(1, "S").source
  local dir = src:match("^@(.*/)") or "./"
  return dir .. "dns-filter-bridge.nft"
end
local substitute
substitute = function(content, plan)
  if plan == nil then
    plan = nil
  end
  local cfg = require("config")
  content = content:gsub("{QUEUE_QUESTIONS}", cfg.nfqueue.questions)
  content = content:gsub("{QUEUE_RESPONSES}", cfg.nfqueue.responses)
  content = content:gsub("{QUEUE_CAPTIVE}", cfg.nfqueue.captive)
  content = content:gsub("{QUEUE_REJECT}", cfg.nfqueue.reject)
  content = content:gsub("{QUEUE_AUTH}", cfg.nfqueue.auth)
  content = content:gsub("{QUEUE_SNI_LOG}", cfg.nfqueue.sni_log)
  content = content:gsub("{NFT_IP_TIMEOUT}", cfg.nft.ip_timeout)
  local compiled_rules
  if plan then
    compiled_rules = nft_compiler.render(plan, "  ", true)
  else
    compiled_rules = "  chain cv_rules_dispatch {\n    return\n  }\n"
  end
  content = content:gsub("{COMPILED_FILTER_RULES}", compiled_rules)
  local sip_rules
  if cfg.nfqueue.sip then
    local q = cfg.nfqueue.sip
    sip_rules = table.concat({
      "    # SIP signalling + STUN → NFQUEUE (worker_sip).",
      "    # Toujours NF_ACCEPT ; apprend les IPs dans sip_peers + mac4/mac6_allowed.",
      "    # dport 5060/5061 capture aussi les réponses opérateur à source port dynamique.",
      "    # bypass : si le worker est absent, le trafic SIP passe quand même.",
      "    meta l4proto {udp, tcp} th dport {5060, 5061} queue num " .. tostring(q) .. " bypass comment \"SIP outbound → NFQUEUE\"",
      "    meta l4proto {udp, tcp} th sport {5060, 5061} queue num " .. tostring(q) .. " bypass comment \"SIP inbound → NFQUEUE\"",
      "    meta l4proto udp        th dport 3478         queue num " .. tostring(q) .. " bypass comment \"STUN/ICE → NFQUEUE\"",
      "    meta l4proto udp        th sport 3478         queue num " .. tostring(q) .. " bypass comment \"STUN/ICE responses → NFQUEUE\""
    }, "\n")
  else
    sip_rules = ""
  end
  content = content:gsub("{SIP_RULES}", sip_rules)
  if get_log_level_num("DEBUG") < get_log_level_num(cfg.runtime.log_level) then
    content = content:gsub("log%s+level%s+debug%s+prefix%s+\"[^\"]*\"", "")
  end
  return content
end
local compile_filter_rules
compile_filter_rules = function(filter_cfg, rules_metadata)
  if rules_metadata == nil then
    rules_metadata = nil
  end
  if not (filter_cfg and filter_cfg.rules and #filter_cfg.rules > 0) then
    return nil
  end
  return nft_compiler.compile(filter_cfg, rules_metadata)
end
local create_filter_rule_sets
create_filter_rule_sets = function(plan)
  if not (plan and plan.rules and #plan.rules > 0) then
    return true
  end
  local commands = nft_dynamic_sets.generate_set_creation_commands(plan)
  if #commands == 0 then
    log_debug({
      action = "no_rule_sets_to_create"
    })
    return true
  end
  log_info({
    action = "creating_per_rule_nft_sets",
    count = #commands
  })
  local all_ok = true
  for _, cmd in ipairs(commands) do
    local ok, err = run_cmd(cmd, {
      quiet = false
    })
    if not (ok) then
      if err and err:find("already exists") then
        log_debug({
          action = "set_already_exists",
          cmd = cmd
        })
      else
        log_warn({
          action = "set_creation_failed",
          cmd = cmd,
          err = err or ""
        })
        all_ok = false
      end
    end
  end
  return all_ok
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
  local cfg = require("config")
  local compiled_rules = rule.compile_rules(cfg.filter)
  local rules_metadata = compiled_rules.rules_metadata
  local plan = compile_filter_rules(cfg.filter, rules_metadata)
  content = substitute(content, plan)
  local tmpdir = "./tmp"
  os.execute("mkdir -p " .. tostring(tmpdir))
  local tmpfile = tostring(tmpdir) .. "/custos-rules-" .. tostring(os.time()) .. ".nft"
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
  os.remove(tmpfile)
  if rc ~= 0 then
    log_warn({
      action = "nft_rules_apply_failed",
      path = path
    })
    return false
  end
  log_info({
    action = "nft_rules_template_applied",
    path = path
  })
  if not (create_filter_rule_sets(plan)) then
    log_warn({
      action = "nft_rules_sets_creation_failed"
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
