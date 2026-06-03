local concat
concat = table.concat
local new
new = function(opts)
  if opts == nil then
    opts = { }
  end
  local resolvers = opts.resolvers or { }
  local verdict_ttl = opts.verdict_ttl_s or 5
  local budget_ms = opts.budget_ms or 80
  local families = opts.families or {
    ipv4 = true,
    ipv6 = true
  }
  local validator_set = { }
  for _index_0 = 1, #resolvers do
    local ip = resolvers[_index_0]
    validator_set[ip] = true
  end
  local verdicts = { }
  local parked = { }
  local corr_key
  corr_key = function(client_ip, txid, qname)
    return concat({
      tostring(client_ip),
      string.format("%04x", txid or 0),
      (qname or ""):lower()
    }, "|")
  end
  local is_validator
  is_validator = function(src_ip)
    return validator_set[src_ip] == true
  end
  local active_for
  active_for = function(version)
    if version == 6 then
      return families.ipv6 == true
    else
      return families.ipv4 == true
    end
  end
  local store_verdict
  store_verdict = function(key, verdict, now_s)
    verdicts[key] = {
      verdict = verdict,
      expires_at = (now_s or 0) + verdict_ttl
    }
  end
  local take_verdict
  take_verdict = function(key, now_s)
    local e = verdicts[key]
    if not (e) then
      return nil
    end
    verdicts[key] = nil
    if now_s and now_s > e.expires_at then
      return nil
    end
    return e.verdict
  end
  local park
  park = function(key, ctx, now_ms)
    parked[key] = {
      ctx = ctx,
      deadline_ms = (now_ms or 0) + budget_ms
    }
  end
  local take_parked
  take_parked = function(key)
    local e = parked[key]
    if not (e) then
      return nil
    end
    parked[key] = nil
    return e.ctx
  end
  local expired
  expired = function(now_ms)
    local out = { }
    for key, e in pairs(parked) do
      if now_ms >= e.deadline_ms then
        out[#out + 1] = e.ctx
        parked[key] = nil
      end
    end
    return out
  end
  local has_parked
  has_parked = function()
    return next(parked) ~= nil
  end
  return {
    corr_key = corr_key,
    is_validator = is_validator,
    active_for = active_for,
    store_verdict = store_verdict,
    take_verdict = take_verdict,
    park = park,
    take_parked = take_parked,
    expired = expired,
    has_parked = has_parked,
    budget_ms = budget_ms
  }
end
return {
  new = new
}
