local config = require("config")
local dns_cfg = config.dns or { }
local ttl_cfg = dns_cfg.ttl_grace or { }
local clamp
clamp = function(value, min_v, max_v)
  if value < min_v then
    return min_v
  end
  if value > max_v then
    return max_v
  end
  return value
end
local rr_timeout
rr_timeout = function(ttl)
  local grace = math.max(0, math.floor(tonumber(ttl_cfg.grace) or 600))
  local min_t = math.max(1, math.floor(tonumber(ttl_cfg.min) or 60))
  local max_t = math.max(min_t, math.floor(tonumber(ttl_cfg.max) or 2592000))
  local rr_ttl = tonumber(ttl) or 0
  rr_ttl = math.floor(rr_ttl)
  if rr_ttl < 0 then
    rr_ttl = 0
  end
  local effective = clamp(rr_ttl + grace, min_t, max_t)
  return tostring(effective) .. "s", effective
end
local detect_wildcards
detect_wildcards = function(rules_metadata)
  local out = { }
  for idx, meta in ipairs(rules_metadata or { }) do
    local requires_auth = false
    local dns_refs = 0
    if meta.conditions then
      for _, cond in ipairs(meta.conditions) do
        if cond.name == "from_users" or cond.name == "from_userlists" then
          requires_auth = true
        end
        if cond.name == "to_domains" or cond.name == "to_domainlist" then
          dns_refs = dns_refs + 1
        end
      end
    end
    if requires_auth and dns_refs == 0 then
      out[#out + 1] = meta.rule_id or "unknown_" .. tostring(idx)
    end
  end
  return out
end
local add_to_wildcards
add_to_wildcards = function(add_fn, wildcard_ids, key, dest, timeout, corr)
  local any_ok = false
  for _, rid in ipairs(wildcard_ids or { }) do
    local ok = add_fn(key, dest, rid, timeout, corr)
    any_ok = any_ok or ok
  end
  return any_ok
end
local inject
inject = function(answers, opts)
  local records_to_add = 0
  local success_any = false
  local ip_count = 0
  local no_v4 = { }
  local no_v6 = { }
  if not (opts.inject_nft) then
    return {
      records_to_add = records_to_add,
      success_any = success_any,
      ip_count = ip_count,
      no_v4 = no_v4,
      no_v6 = no_v6
    }
  end
  local timeout_of = opts.timeout_of or rr_timeout
  local mac_valid = opts.mac_valid
  local use_wild = opts.user and opts.wildcard_ids and #opts.wildcard_ids > 0
  local mac_ok = mac_valid(opts.client_mac)
  for _index_0 = 1, #answers do
    local ans = answers[_index_0]
    local fam = ans.family
    local add_ip = opts.add_ip[fam]
    local add_mac = opts.add_mac[fam]
    local client = opts.client_addr(fam)
    local timeout = timeout_of(ans.ttl)
    if client then
      records_to_add = records_to_add + 1
      local ok = add_ip(client, ans.addr, opts.rule_id, timeout, opts.ack_corr)
      if ok then
        ip_count = ip_count + 1
      end
      success_any = success_any or ok
      if use_wild then
        local w_ok = add_to_wildcards(add_ip, opts.wildcard_ids, client, ans.addr, timeout, opts.ack_corr)
        success_any = success_any or w_ok
      end
    else
      local tbl = fam == "ipv4" and no_v4 or no_v6
      tbl[#tbl + 1] = ans.addr
    end
    if mac_ok then
      local m_ok = add_mac(opts.client_mac, ans.addr, opts.rule_id, timeout, opts.ack_corr)
      success_any = success_any or m_ok
      if use_wild then
        local wm_ok = add_to_wildcards(add_mac, opts.wildcard_ids, opts.client_mac, ans.addr, timeout, opts.ack_corr)
        success_any = success_any or wm_ok
      end
    end
  end
  return {
    records_to_add = records_to_add,
    success_any = success_any,
    ip_count = ip_count,
    no_v4 = no_v4,
    no_v6 = no_v6
  }
end
return {
  rr_timeout = rr_timeout,
  detect_wildcards = detect_wildcards,
  add_to_wildcards = add_to_wildcards,
  inject = inject
}
