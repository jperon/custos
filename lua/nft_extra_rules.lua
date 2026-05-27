local ffi, libnft
do
  local _obj_0 = require("ffi_defs")
  ffi, libnft = _obj_0.ffi, _obj_0.libnft
end
local config = require("config")
local log_warn, log_info
do
  local _obj_0 = require("log")
  log_warn, log_info = _obj_0.log_warn, _obj_0.log_info
end
local ctx = libnft.nft_ctx_new(0)
if ctx == nil then
  error("nft_ctx_new() échoué dans nft_extra_rules")
end
local inserted_rules = { }
local run_cmd
run_cmd = function(cmd)
  local rc = libnft.nft_run_cmd_from_buffer(ctx, cmd)
  if rc ~= 0 then
    local ts = os.time()
    log_warn(function()
      return {
        action = "nft_extra_cmd_failed",
        cmd = cmd,
        rc = rc,
        ts = ts
      }
    end)
    return false, rc
  end
  return true, 0
end
local find_handles_for_fragment
find_handles_for_fragment = function(fragment)
  local handles = { }
  local cmd = "nft -a list chain " .. tostring(config.nft.family) .. " " .. tostring(config.nft.table) .. " forward 2>/dev/null"
  local fh = io.popen(cmd)
  if not (fh) then
    return handles
  end
  local out = fh:read("*a")
  fh:close()
  if out and #out > 0 then
    for line in out:gmatch("[^\n]+") do
      if line:find(fragment, 1, true) then
        local h = line:match("handle%s+(%d+)")
        if h then
          table.insert(handles, tonumber(h))
        end
      end
    end
  end
  return handles
end
local init
init = function(rules)
  inserted_rules = { }
  if not (rules and #rules > 0) then
    return true
  end
  local all_ok = true
  for i = #rules, 1, -1 do
    local _continue_0 = false
    repeat
      local r = tostring(rules[i]:gsub("%s+", " "))
      r = r:match("^%s*(.-)%s*$")
      if #r == 0 then
        _continue_0 = true
        break
      end
      local handles = find_handles_for_fragment(r)
      if handles and #handles > 0 then
        for _index_0 = 1, #handles do
          local h = handles[_index_0]
          local del_cmd = "delete rule " .. tostring(config.nft.family) .. " " .. tostring(config.nft.table) .. " forward handle " .. tostring(h)
          local removed, rc = run_cmd(del_cmd)
          if removed then
            log_info(function()
              return {
                action = "nft_extra_rule_removed_existing",
                rule = r,
                handle = h
              }
            end)
          else
            log_warn(function()
              return {
                action = "nft_extra_rule_remove_failed",
                rule = r,
                handle = h,
                rc = rc
              }
            end)
          end
        end
      end
      local insert_cmd = "insert rule " .. tostring(config.nft.family) .. " " .. tostring(config.nft.table) .. " forward position 0 " .. tostring(r)
      local ok, rc = run_cmd(insert_cmd)
      if ok then
        table.insert(inserted_rules, r)
        log_info(function()
          return {
            action = "nft_extra_rule_added",
            rule = r
          }
        end)
      else
        all_ok = false
        log_warn(function()
          return {
            action = "nft_extra_rule_add_failed",
            rule = r,
            rc = rc
          }
        end)
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  return all_ok
end
local populate_filter_ips
populate_filter_ips = function()
  local family = config.nft.family
  local tbl = config.nft.table
  local fh = io.popen("ip -4 addr show 2>/dev/null")
  if fh then
    for line in fh:lines() do
      local ip = line:match("%s+inet%s+([%d%.]+)/")
      if ip then
        local ok = run_cmd("add element " .. tostring(family) .. " " .. tostring(tbl) .. " filter_ips4 { " .. tostring(ip) .. " }")
        log_info(function()
          if ok then
            return {
              action = "nft_filter_ip4_added",
              ip = ip
            }
          end
        end)
      end
    end
    fh:close()
  end
  fh = io.popen("ip -6 addr show 2>/dev/null")
  if fh then
    for line in fh:lines() do
      local ip6 = line:match("%s+inet6%s+([%x:]+)/")
      if ip6 and not ip6:match("^fe80") then
        local ok = run_cmd("add element " .. tostring(family) .. " " .. tostring(tbl) .. " filter_ips6 { " .. tostring(ip6) .. " }")
        log_info(function()
          if ok then
            return {
              action = "nft_filter_ip6_added",
              ip = ip6
            }
          end
        end)
      end
    end
    return fh:close()
  end
end
local apply_from_config
apply_from_config = function()
  local rc_check = os.execute("nft list chain " .. tostring(config.nft.family) .. " " .. tostring(config.nft.table) .. " forward >/dev/null 2>&1")
  if rc_check ~= 0 then
    local ok, rc = require("nft_rules").apply()
    if not (ok) then
      log_warn(function()
        return {
          action = "nft_extra_main_rules_reapply_failed",
          rc = rc or -1
        }
      end)
      return false
    end
    log_info(function()
      return {
        action = "nft_extra_main_rules_reapplied"
      }
    end)
  end
  populate_filter_ips()
  local cfg = require("config")
  local rules = cfg.nft.extra_rules or { }
  return init(rules)
end
local cleanup
cleanup = function()
  local rules_to_clean = { }
  if inserted_rules and #inserted_rules > 0 then
    for _index_0 = 1, #inserted_rules do
      local r = inserted_rules[_index_0]
      table.insert(rules_to_clean, r)
    end
  end
  local ok, cfg = pcall(function()
    return require("config")
  end)
  if ok and cfg and cfg.nft and cfg.nft.extra_rules then
    local _list_0 = cfg.nft.extra_rules
    for _index_0 = 1, #_list_0 do
      local r = _list_0[_index_0]
      if r and #tostring(r) > 0 then
        table.insert(rules_to_clean, tostring(r))
      end
    end
  end
  local seen = { }
  local uniq = { }
  for _index_0 = 1, #rules_to_clean do
    local r = rules_to_clean[_index_0]
    if not seen[r] then
      seen[r] = true
      table.insert(uniq, r)
    end
  end
  rules_to_clean = uniq
  if #rules_to_clean > 0 then
    for _index_0 = 1, #rules_to_clean do
      local _continue_0 = false
      repeat
        local r = rules_to_clean[_index_0]
        r = tostring(r:gsub("%s+", " "))
        r = r:match("^%s*(.-)%s*$")
        if #r == 0 then
          _continue_0 = true
          break
        end
        local handles = find_handles_for_fragment(r)
        if handles and #handles > 0 then
          for _index_1 = 1, #handles do
            local h = handles[_index_1]
            local cmd = "delete rule " .. tostring(config.nft.family) .. " " .. tostring(config.nft.table) .. " forward handle " .. tostring(h)
            local rc
            ok, rc = run_cmd(cmd)
            if ok then
              log_info(function()
                return {
                  action = "nft_extra_rule_removed_on_cleanup",
                  rule = r,
                  handle = h
                }
              end)
            else
              log_warn(function()
                return {
                  action = "nft_extra_rule_delete_failed",
                  rule = r,
                  handle = h,
                  rc = rc
                }
              end)
            end
          end
        end
        _continue_0 = true
      until true
      if not _continue_0 then
        break
      end
    end
    inserted_rules = { }
  end
  if ctx ~= nil then
    return libnft.nft_ctx_free(ctx)
  end
end
return {
  init = init,
  cleanup = cleanup,
  apply_from_config = apply_from_config,
  run_cmd = run_cmd
}
