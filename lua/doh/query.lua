local dns_mod = require("ipparse.l7.dns")
local parse = dns_mod.parse
local QTYPE
QTYPE = require("ipparse.l7.dns").types
local decide_meta, run_on_response
do
  local _obj_0 = require("filter")
  decide_meta, run_on_response = _obj_0.decide_meta, _obj_0.run_on_response
end
local add_ip4, add_ip6, add_mac4, add_mac6, get_last_seq, wait_ack, drain_ack
do
  local _obj_0 = require("nft_queue")
  add_ip4, add_ip6, add_mac4, add_mac6, get_last_seq, wait_ack, drain_ack = _obj_0.add_ip4, _obj_0.add_ip6, _obj_0.add_mac4, _obj_0.add_mac6, _obj_0.get_last_seq, _obj_0.wait_ack, _obj_0.drain_ack
end
local build_blocked_response, add_ede, patch_modified_dns
do
  local _obj_0 = require("dns_ede")
  build_blocked_response, add_ede, patch_modified_dns = _obj_0.build_blocked_response, _obj_0.add_ede, _obj_0.patch_modified_dns
end
local inject, detect_wildcards
do
  local _obj_0 = require("response_inject")
  inject, detect_wildcards = _obj_0.inject, _obj_0.detect_wildcards
end
local user_for_mac
user_for_mac = require("auth.sessions").user_for_mac
local log_allow, log_block, log_warn, log_debug, log_info
do
  local _obj_0 = require("log")
  log_allow, log_block, log_warn, log_debug, log_info = _obj_0.log_allow, _obj_0.log_block, _obj_0.log_warn, _obj_0.log_debug, _obj_0.log_info
end
local config = require("config")
local upstream_mod = require("doh.upstream")
local MAC_ZERO = "00:00:00:00:00:00"
local mac_valid
mac_valid = function(mac)
  return mac and mac ~= "unknown" and mac ~= MAC_ZERO
end
local rr_addr
rr_addr = function(ans)
  if ans.rtype == QTYPE.A and ans.rdata and #ans.rdata == 4 then
    return tostring(ans.rdata:byte(1)) .. "." .. tostring(ans.rdata:byte(2)) .. "." .. tostring(ans.rdata:byte(3)) .. "." .. tostring(ans.rdata:byte(4))
  end
  if ans.rtype == QTYPE.AAAA and ans.rdata and #ans.rdata == 16 then
    local words = { }
    for i = 1, 16, 2 do
      words[#words + 1] = string.format("%x", ans.rdata:byte(i) * 256 + ans.rdata:byte(i + 1))
    end
    return table.concat(words, ":")
  end
  return ans.rdata_str
end
local wildcard_ids = { }
local set_wildcard_rules
set_wildcard_rules = function(rules_metadata)
  wildcard_ids = detect_wildcards(rules_metadata)
  return log_info(function()
    return {
      action = "doh_auth_wildcard_rules_loaded",
      count = #wildcard_ids,
      rules = table.concat(wildcard_ids, ", ")
    }
  end)
end
local normalize_answers
normalize_answers = function(resp_dns)
  local out = { }
  local _list_0 = (resp_dns.answers or { })
  for _index_0 = 1, #_list_0 do
    local _continue_0 = false
    repeat
      local ans = _list_0[_index_0]
      if not (ans.rtype == QTYPE.A or ans.rtype == QTYPE.AAAA) then
        _continue_0 = true
        break
      end
      local addr = rr_addr(ans)
      if not (addr and addr ~= "") then
        _continue_0 = true
        break
      end
      out[#out + 1] = {
        family = (ans.rtype == QTYPE.AAAA and "ipv6" or "ipv4"),
        addr = addr,
        ttl = ans.ttl
      }
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  return out
end
local process_query
process_query = function(dns_raw, client_ip, client_mac, upstream)
  local dns, parse_err = parse(dns_raw, 1, false)
  if not (dns) then
    log_warn(function()
      return {
        action = "parse_failed",
        client_ip = client_ip,
        err = tostring(parse_err)
      }
    end)
    return nil, "dns_parse_failed"
  end
  local user = user_for_mac(client_mac, client_ip, config.auth.sessions_file)
  log_debug(function()
    return {
      action = "process_query",
      client_ip = client_ip,
      client_mac = client_mac,
      user = user,
      query_bytes = #dns_raw
    }
  end)
  local block_reason = nil
  local allow_reason = nil
  local blocked_dns = nil
  local any_blocked = false
  local allow_rule_id = nil
  local allow_timeout = nil
  local allow_response_rule_ids = { }
  local questions = dns.questions or (dns.question and {
    dns.question
  } or { })
  for _index_0 = 1, #questions do
    local q = questions[_index_0]
    local qname_text = q.name or q.qname
    local req = {
      domain = qname_text,
      src_ip = client_ip,
      mac = client_mac,
      ts = os.time(),
      user = user
    }
    log_debug(function()
      return {
        action = "filter_decide",
        qname = qname_text,
        qtype = q.qtype_name or tostring(q.qtype),
        client_ip = client_ip
      }
    end)
    local meta = decide_meta(req)
    local fields = {
      action = (function()
        if meta.verdict then
          return "allow"
        else
          return "block"
        end
      end)(),
      worker = "doh",
      qname = qname_text,
      qtype = q.qtype_name or tostring(q.qtype),
      client_ip = client_ip,
      client_mac = client_mac,
      user = user,
      reason = meta.reason or "",
      rule = meta.description or ""
    }
    if meta.verdict then
      log_allow(function()
        return fields
      end)
      allow_reason = meta.reason
      allow_rule_id = meta.rule_id
      allow_timeout = meta.timeout
      allow_response_rule_ids = meta.response_rule_ids or { }
    else
      log_block(function()
        return fields
      end)
      any_blocked = true
      block_reason = meta.reason
    end
  end
  if any_blocked then
    local blocked = build_blocked_response(dns, dns_raw, block_reason)
    if not (blocked) then
      log_warn(function()
        return {
          action = "blocked_build_failed",
          client_ip = client_ip,
          reason = block_reason
        }
      end)
      return nil, "blocked_response_build_failed"
    end
    log_debug(function()
      return {
        action = "query_blocked",
        client_ip = client_ip,
        reason = block_reason
      }
    end)
    return blocked
  end
  local resp_raw, upstream_err = upstream_mod.query(upstream, dns_raw)
  if not (resp_raw) then
    log_warn(function()
      return {
        action = "upstream_failed",
        client_ip = client_ip,
        err = upstream_err
      }
    end)
    return nil, upstream_err or "upstream_failed"
  end
  local response_hooks = (#allow_response_rule_ids > 0) and allow_response_rule_ids or allow_rule_id
  local resp_ctx = run_on_response(response_hooks, resp_raw, allow_reason, {
    resolver_ip = upstream
  })
  resp_raw = resp_ctx.dns_raw
  local resp_dns, resp_err = parse(resp_raw, 1, false)
  if not (resp_dns) then
    log_warn(function()
      return {
        action = "response_parse_failed",
        client_ip = client_ip,
        err = tostring(resp_err) or "unknown"
      }
    end)
    return resp_raw
  end
  local is_v6_client = (client_ip:find(":")) ~= nil
  local client_addr
  client_addr = function(fam)
    return (fam == "ipv4" and not is_v6_client) and client_ip or (fam == "ipv6" and is_v6_client) and client_ip or nil
  end
  local ack_corr = string.format("%04x:%s", dns.txid or 0, client_ip or "unknown")
  local answers = normalize_answers(resp_dns)
  if resp_ctx.inject_nft then
    drain_ack()
  end
  local inj = inject(answers, {
    client_addr = client_addr,
    client_mac = client_mac,
    user = user,
    rule_id = allow_rule_id or "unknown_rule",
    wildcard_ids = wildcard_ids,
    ack_corr = ack_corr,
    inject_nft = resp_ctx.inject_nft,
    mac_valid = mac_valid,
    add_ip = {
      ipv4 = add_ip4,
      ipv6 = add_ip6
    },
    add_mac = {
      ipv4 = add_mac4,
      ipv6 = add_mac6
    }
  })
  local failure_policy = (config.nft or { }).add_failure_policy or "fail-closed"
  if inj.records_to_add > 0 and not inj.success_any and failure_policy == "fail-closed" then
    log_block(function()
      return {
        action = "doh_nft_add_failed_fail_closed",
        client_ip = client_ip,
        client_mac = client_mac,
        user = user,
        rule = allow_rule_id
      }
    end)
    local blocked = build_blocked_response(dns, dns_raw, "nft_insert_failed")
    return blocked or resp_raw
  end
  local _
  resp_raw, _ = patch_modified_dns(resp_raw, allow_reason)
  if resp_ctx.inject_nft then
    local pending_seq = get_last_seq()
    if pending_seq then
      wait_ack(pending_seq, ack_corr)
    end
  end
  log_debug(function()
    return {
      action = resp_ctx.action_label or "query_allowed",
      client_ip = client_ip,
      client_mac = client_mac,
      user = user,
      answers = inj.ip_count,
      inject_nft = resp_ctx.inject_nft,
      modified = resp_ctx.modified,
      reason = allow_reason or ""
    }
  end)
  return resp_raw
end
return {
  process_query = process_query,
  set_wildcard_rules = set_wildcard_rules,
  normalize_answers = normalize_answers
}
