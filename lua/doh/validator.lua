local upstream_mod = require("doh.upstream")
local parse
parse = require("ipparse.l7.dns").parse
local dns_classify = require("dns_classify")
local log_debug, log_warn
do
  local _obj_0 = require("log")
  log_debug, log_warn = _obj_0.log_debug, _obj_0.log_warn
end
local RCODE_REFUSED = 5
local verdict_to_override
verdict_to_override = function(vi)
  local _exp_0 = vi.verdict
  if "block" == _exp_0 then
    return {
      kind = "block"
    }
  elseif "sinkhole" == _exp_0 then
    return {
      kind = "sinkhole",
      a = vi.a,
      aaaa = vi.aaaa,
      ttl = vi.ttl
    }
  elseif "redirect" == _exp_0 then
    return {
      kind = "redirect",
      cname_target = vi.cname_target,
      a = vi.a,
      aaaa = vi.aaaa,
      ttl = vi.ttl
    }
  else
    return nil
  end
end
local upstream_curl_mod = nil
local get_doh_mod
get_doh_mod = function()
  upstream_curl_mod = upstream_curl_mod or require("doh.upstream_doh_curl")
  return upstream_curl_mod
end
local open_client
open_client = function(endpoint, timeout_ms)
  if endpoint:sub(1, 8) == "https://" then
    return get_doh_mod().new_client(endpoint, timeout_ms)
  else
    return upstream_mod.new_client(endpoint, 53, timeout_ms)
  end
end
local close_client
close_client = function(client)
  if client._mod then
    return client._mod.close(client)
  else
    return upstream_mod.close(client)
  end
end
local do_query
do_query = function(client, dns_raw)
  if client._mod then
    return client._mod.query(client, dns_raw)
  else
    return upstream_mod.query(client, dns_raw)
  end
end
local query_classified
query_classified = function(dns_raw, resolvers, timeout_ms, doh_timeout_ms)
  if timeout_ms == nil then
    timeout_ms = 1000
  end
  if doh_timeout_ms == nil then
    doh_timeout_ms = 3000
  end
  for _index_0 = 1, #resolvers do
    local _continue_0 = false
    repeat
      do
        local endpoint = resolvers[_index_0]
        local is_doh = endpoint:sub(1, 8) == "https://"
        local t_ms = is_doh and doh_timeout_ms or timeout_ms
        local client, c_err = open_client(endpoint, t_ms)
        if not (client) then
          log_warn(function()
            return {
              action = "validator_connect_failed",
              resolver_ip = endpoint,
              err = c_err
            }
          end)
          _continue_0 = true
          break
        end
        local resp_raw, q_err = do_query(client, dns_raw)
        close_client(client)
        if not (resp_raw) then
          log_warn(function()
            return {
              action = "validator_query_failed",
              resolver_ip = endpoint,
              err = q_err
            }
          end)
          _continue_0 = true
          break
        end
        local resp_dns = parse(resp_raw, 1, false)
        if not (resp_dns) then
          log_warn(function()
            return {
              action = "validator_parse_failed",
              resolver_ip = endpoint
            }
          end)
          _continue_0 = true
          break
        end
        if dns_classify.numeric_rcode(resp_dns.header) == RCODE_REFUSED then
          log_debug(function()
            return {
              action = "validator_verdict",
              resolver_ip = endpoint,
              verdict = "block_refused"
            }
          end)
          return {
            kind = "block"
          }, "validator=" .. tostring(endpoint) .. " rcode=REFUSED"
        end
        local vi = dns_classify.classify(resp_dns, resp_raw)
        log_debug(function()
          return {
            action = "validator_verdict",
            resolver_ip = endpoint,
            verdict = vi.verdict
          }
        end)
        local override = verdict_to_override(vi)
        return override, (override and "validator=" .. tostring(endpoint) .. " verdict=" .. tostring(vi.verdict) or nil)
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  log_warn(function()
    return {
      action = "validator_all_failed",
      count = #resolvers
    }
  end)
  return nil, nil
end
local query_verdict
query_verdict = function(dns_raw, resolvers, timeout_ms, doh_timeout_ms)
  if timeout_ms == nil then
    timeout_ms = 1000
  end
  if doh_timeout_ms == nil then
    doh_timeout_ms = 3000
  end
  local override, reason = query_classified(dns_raw, resolvers, timeout_ms, doh_timeout_ms)
  return (override ~= nil), reason
end
return {
  query_verdict = query_verdict,
  query_classified = query_classified
}
