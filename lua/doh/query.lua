local dns_mod = require("ipparse.l7.dns")
local parse = dns_mod.parse
local QTYPE
QTYPE = require("ipparse.l7.dns").types
local decide_meta
decide_meta = require("filter").decide_meta
local add_ip4, add_ip6, add_mac4, add_mac6, get_last_seq, wait_ack
do
  local _obj_0 = require("nft_queue")
  add_ip4, add_ip6, add_mac4, add_mac6, get_last_seq, wait_ack = _obj_0.add_ip4, _obj_0.add_ip6, _obj_0.add_mac4, _obj_0.add_mac6, _obj_0.get_last_seq, _obj_0.wait_ack
end
local build_blocked_response, add_ede
do
  local _obj_0 = require("dns_ede")
  build_blocked_response, add_ede = _obj_0.build_blocked_response, _obj_0.add_ede
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
local inject_answers
inject_answers = function(answers, client_ip, client_mac, rule_id, timeout, ack_corr)
  rule_id = rule_id or "unknown_rule"
  timeout = timeout or config.nft.ip_timeout
  local is_v6_client = (client_ip:find(":")) ~= nil
  for _index_0 = 1, #answers do
    local _continue_0 = false
    repeat
      local ans = answers[_index_0]
      local addr = rr_addr(ans)
      if not (addr and addr ~= "") then
        _continue_0 = true
        break
      end
      if ans.rtype == QTYPE.A then
        if not (is_v6_client) then
          log_debug(function()
            return {
              action = "nft_add_ip4",
              client_ip = client_ip,
              dest = addr
            }
          end)
          add_ip4(client_ip, addr, rule_id, timeout, ack_corr)
        end
        if mac_valid(client_mac) then
          log_debug(function()
            return {
              action = "nft_add_mac4",
              client_mac = client_mac,
              dest = addr
            }
          end)
          add_mac4(client_mac, addr, rule_id, timeout, ack_corr)
        end
      elseif ans.rtype == QTYPE.AAAA then
        if is_v6_client then
          log_debug(function()
            return {
              action = "nft_add_ip6",
              client_ip = client_ip,
              dest = addr
            }
          end)
          add_ip6(client_ip, addr, rule_id, timeout, ack_corr)
        end
        if mac_valid(client_mac) then
          log_debug(function()
            return {
              action = "nft_add_mac6",
              client_mac = client_mac,
              dest = addr
            }
          end)
          add_mac6(client_mac, addr, rule_id, timeout, ack_corr)
        end
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  local pending_seq = get_last_seq()
  if pending_seq then
    return wait_ack(pending_seq, ack_corr)
  end
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
  local resp_dns, resp_err = parse(resp_raw, 1, false)
  if resp_dns then
    local answers = resp_dns.answers or { }
    local ack_corr = string.format("%04x:%s", dns.txid or 0, client_ip or "unknown")
    inject_answers(answers, client_ip, client_mac, allow_rule_id, allow_timeout, ack_corr)
    log_debug(function()
      return {
        action = "query_allowed",
        client_ip = client_ip,
        client_mac = client_mac,
        user = user,
        answers = #answers,
        reason = allow_reason or ""
      }
    end)
  else
    log_warn(function()
      return {
        action = "response_parse_failed",
        client_ip = client_ip,
        err = tostring(resp_err) or "unknown"
      }
    end)
  end
  return resp_raw
end
return {
  process_query = process_query
}
