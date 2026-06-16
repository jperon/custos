local build_cname_response
build_cname_response = require("dns_ede").build_cname_response
local dns_mod = require("ipparse.l7.dns")
local encode_dns_name
encode_dns_name = require("lib.dns_name").encode_dns_name
local bit = require("bit")
local QTYPE_A = dns_mod.types.A
local QTYPE_AAAA = dns_mod.types.AAAA
local NOERROR = dns_mod.rcodes.NOERROR
local _clients = { }
local _rr_cache = { }
local _dead_resolvers = { }
local DEAD_RESOLVER_TTL = 30
local pick_resolver_ip
pick_resolver_ip = function(cfg, ctx)
  if ctx and ctx.resolver_ip and ctx.resolver_ip ~= "" then
    return ctx.resolver_ip
  end
  local doh = cfg and cfg.doh or { }
  if doh.prefer_ipv6 and doh.upstream_ipv6 and doh.upstream_ipv6 ~= "" then
    return doh.upstream_ipv6
  end
  return doh.upstream_ipv4 or doh.upstream_ipv6
end
local get_upstream_client
get_upstream_client = function(cfg, resolver_ip)
  if not (resolver_ip and resolver_ip ~= "") then
    return nil
  end
  local cached = _clients[resolver_ip]
  if cached then
    return cached
  end
  local ok, upstream_mod = pcall(require, "doh.upstream")
  if not (ok and upstream_mod) then
    return nil
  end
  local doh = cfg and cfg.doh or { }
  local port = doh.upstream_port or 53
  local timeout_ms = doh.upstream_timeout_ms or 2000
  local client, _ = upstream_mod.new_client(resolver_ip, port, timeout_ms)
  _clients[resolver_ip] = client
  return client
end
local build_query
build_query = function(name, qtype, txid)
  local q = dns_mod.new({
    header = dns_mod.new_header({
      id = txid,
      rd = true
    }),
    questions = {
      {
        qname = encode_dns_name(name),
        qtype = qtype,
        qclass = 1
      }
    }
  })
  return tostring(q)
end
local dedupe_raw
dedupe_raw = function(list)
  local set = { }
  local out = { }
  for _index_0 = 1, #list do
    local raw = list[_index_0]
    if not (set[raw]) then
      set[raw] = true
      out[#out + 1] = raw
    end
  end
  return out
end
local resolve_target_rrs
resolve_target_rrs = function(cfg, target, resolver_ip)
  if not (target and target ~= "") then
    return nil
  end
  if not (resolver_ip and resolver_ip ~= "") then
    return nil
  end
  local cache_key = tostring(resolver_ip) .. "|" .. tostring(target)
  local now = os.time()
  local cached = _rr_cache[cache_key]
  if cached and cached.expires_at > now then
    return {
      a = cached.a,
      aaaa = cached.aaaa,
      ttl = cached.ttl
    }
  end
  local dead_until = _dead_resolvers[resolver_ip]
  if dead_until and dead_until > now then
    return nil
  end
  local client = get_upstream_client(cfg, resolver_ip)
  if not (client) then
    return nil
  end
  local records = {
    a = { },
    aaaa = { }
  }
  local ttl = 300
  local any_response = false
  for qtype, key in pairs({
    [QTYPE_A] = "a",
    [QTYPE_AAAA] = "aaaa"
  }) do
    local txid = math.random(0, 0xFFFF)
    local query = build_query(target, qtype, txid)
    local ok, resp_raw = pcall((function()
      return (require("doh.upstream")).query(client, query)
    end))
    if ok and resp_raw then
      any_response = true
      local resp = dns_mod.parse(resp_raw, 1, false)
      local rcode = resp and resp.header and bit.band(resp.header.ra_z_rcode or 0, 0x0f)
      if resp and resp.header and rcode == NOERROR then
        local _list_0 = (resp.answers or { })
        for _index_0 = 1, #_list_0 do
          local rr = _list_0[_index_0]
          if rr.rtype == qtype then
            if (qtype == QTYPE_A and #rr.rdata == 4) or (qtype == QTYPE_AAAA and #rr.rdata == 16) then
              records[key][#records[key] + 1] = rr.rdata
              local rr_ttl = tonumber(rr.ttl) or 300
              if rr_ttl > 0 and rr_ttl < ttl then
                ttl = rr_ttl
              end
            end
          end
        end
      end
    end
  end
  if not (any_response) then
    local dead_ttl = (cfg and cfg.doh and cfg.doh.upstream_dead_ttl_s) or DEAD_RESOLVER_TTL
    _dead_resolvers[resolver_ip] = now + dead_ttl
    return nil
  end
  _dead_resolvers[resolver_ip] = nil
  records.a = dedupe_raw(records.a)
  records.aaaa = dedupe_raw(records.aaaa)
  if #records.a == 0 and #records.aaaa == 0 then
    return nil
  end
  if ttl <= 0 then
    ttl = 300
  end
  if ttl < 30 then
    ttl = 30
  end
  if ttl > 300 then
    ttl = 300
  end
  records.ttl = ttl
  _rr_cache[cache_key] = {
    a = records.a,
    aaaa = records.aaaa,
    ttl = records.ttl,
    expires_at = now + ttl
  }
  return records
end
local _schema = {
  label = "Réécriture CNAME",
  description = "Réécrit la réponse en un CNAME vers la cible configurée",
  arg_type = "string",
  arg_hint = "ex: forcesafesearch.google.com"
}
local qname_of
qname_of = function(dns_raw)
  if not (dns_raw) then
    return nil
  end
  local ok, dns = pcall((function()
    return dns_mod.parse(dns_raw, 1, false)
  end))
  if not (ok and dns and dns.question and dns.question.name) then
    return nil
  end
  local name = dns.question.name:lower()
  return name:gsub("%.+$", "")
end
local rrs_from_response
rrs_from_response = function(dns_raw, target)
  if not (dns_raw and target and target ~= "") then
    return nil
  end
  local ok, dns = pcall((function()
    return dns_mod.parse(dns_raw, 1, false)
  end))
  if not (ok and dns and dns.answers) then
    return nil
  end
  local want = target:lower():gsub("%.+$", "")
  local a, aaaa = { }, { }
  local ttl = 300
  local _list_0 = dns.answers
  for _index_0 = 1, #_list_0 do
    local _continue_0 = false
    repeat
      local rr = _list_0[_index_0]
      local name = rr.name and rr.name:lower():gsub("%.+$", "")
      if not (name == want) then
        _continue_0 = true
        break
      end
      if rr.rtype == QTYPE_A and rr.rdata and #rr.rdata == 4 then
        a[#a + 1] = rr.rdata
      elseif rr.rtype == QTYPE_AAAA and rr.rdata and #rr.rdata == 16 then
        aaaa[#aaaa + 1] = rr.rdata
      else
        _continue_0 = true
        break
      end
      local rr_ttl = tonumber(rr.ttl) or 300
      if rr_ttl > 0 and rr_ttl < ttl then
        ttl = rr_ttl
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  if #a == 0 and #aaaa == 0 then
    return nil
  end
  return {
    a = a,
    aaaa = aaaa,
    ttl = ttl
  }
end
local _factory
_factory = function(cfg)
  return function(rule)
    local target = rule.cname
    local names = rule.cname_names
    return {
      capabilities = {
        worker = true,
        nft = false
      },
      redirects_destination = true,
      cname_target = target,
      eval = function(req)
        return nil, "CNAME → " .. tostring(target) .. " by rule: " .. tostring(rule.description or '?')
      end,
      on_response = function(ctx)
        if names then
          local qname = qname_of(ctx.dns_raw)
          if not (qname and names[qname]) then
            return 
          end
        end
        local target_rrs = rrs_from_response(ctx.dns_raw, target)
        if not (target_rrs) then
          local resolver_ip = pick_resolver_ip(cfg, ctx)
          target_rrs = resolve_target_rrs(cfg, target, resolver_ip)
        end
        local rewritten = build_cname_response(nil, ctx.dns_raw, target, ctx.reason, target_rrs)
        if rewritten then
          ctx.dns_raw = rewritten
          ctx.modified = true
        end
        local has_target_ips = target_rrs and ((#target_rrs.a > 0) or (#target_rrs.aaaa > 0))
        ctx.skip_nft = not has_target_ips
        ctx.action_label = has_target_ips and "response_cname_resolved" or "response_cname"
      end,
      compile_nft = function() end,
      verdict = function()
        return "accept"
      end
    }
  end
end
return {
  schema = _schema,
  factory = _factory,
  resolve_target_rrs = resolve_target_rrs,
  pick_resolver_ip = pick_resolver_ip
}
