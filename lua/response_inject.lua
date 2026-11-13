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
  local groups = { }
  local order = { }
  local add_addr
  add_addr = function(add_fn, rule_id, key, addr, timeout)
    for _index_0 = 1, #order do
      local g = order[_index_0]
      if g.add_fn == add_fn and g.rule_id == rule_id and g.key == key and g.timeout == timeout then
        g.addrs[#g.addrs + 1] = addr
        return 
      end
    end
    order[#order + 1] = {
      add_fn = add_fn,
      rule_id = rule_id,
      key = key,
      timeout = timeout,
      addrs = {
        addr
      }
    }
    return nil
  end
  for _index_0 = 1, #answers do
    local ans = answers[_index_0]
    local fam = ans.family
    local add_ip = opts.add_ip[fam]
    local add_mac = opts.add_mac[fam]
    local client = opts.client_addr(fam)
    local timeout = timeout_of(ans.ttl)
    if client then
      records_to_add = records_to_add + 1
      add_addr(add_ip, opts.rule_id, client, ans.addr, timeout)
      if use_wild then
        local _list_0 = opts.wildcard_ids
        for _index_1 = 1, #_list_0 do
          local rid = _list_0[_index_1]
          add_addr(add_ip, rid, client, ans.addr, timeout)
        end
      end
    else
      local tbl = fam == "ipv4" and no_v4 or no_v6
      tbl[#tbl + 1] = ans.addr
    end
    if mac_ok then
      add_addr(add_mac, opts.rule_id, opts.client_mac, ans.addr, timeout)
      if use_wild then
        local _list_0 = opts.wildcard_ids
        for _index_1 = 1, #_list_0 do
          local rid = _list_0[_index_1]
          add_addr(add_mac, rid, opts.client_mac, ans.addr, timeout)
        end
      end
    end
  end
  for _index_0 = 1, #order do
    local g = order[_index_0]
    local n = g.add_fn(g.key, g.addrs, g.rule_id, g.timeout, opts.ack_corr)
    if n and n > 0 then
      success_any = true
      if g.rule_id == opts.rule_id and (g.add_fn == opts.add_ip.ipv4 or g.add_fn == opts.add_ip.ipv6) then
        ip_count = ip_count + n
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
  inject = inject
}
