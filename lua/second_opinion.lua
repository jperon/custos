local concat
concat = table.concat
local to_hex, from_hex, split_fields, is_ipv4_str, is_ipv6_str
do
  local _obj_0 = require("lib.ipc_hex")
  to_hex, from_hex, split_fields, is_ipv4_str, is_ipv6_str = _obj_0.to_hex, _obj_0.from_hex, _obj_0.split_fields, _obj_0.is_ipv4_str, _obj_0.is_ipv6_str
end
local VERDICT_PREFIX = "v1"
local MAX_VERDICT_LINE = 2048
local MAX_VERDICT_ADDRS = 16
local _KIND_TO_CODE = {
  block = "b",
  sinkhole = "s",
  redirect = "r",
  pass = "p"
}
local _CODE_TO_KIND = {
  b = "block",
  s = "sinkhole",
  r = "redirect",
  p = "pass"
}
local _encode_addrs
_encode_addrs = function(list)
  local parts = { }
  local _list_0 = (list or { })
  for _index_0 = 1, #_list_0 do
    local _continue_0 = false
    repeat
      local r = _list_0[_index_0]
      if #parts >= MAX_VERDICT_ADDRS then
        break
      end
      if not (r and (#r == 4 or #r == 16)) then
        _continue_0 = true
        break
      end
      parts[#parts + 1] = to_hex(r)
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  return concat(parts, ",")
end
local _decode_addrs
_decode_addrs = function(s, want_len)
  local out = { }
  if not (s and s ~= "") then
    return out, nil
  end
  for h in s:gmatch("[^,]+") do
    local raw, err = from_hex(h)
    if err then
      return nil, "addr_" .. tostring(err)
    end
    if not (#raw == want_len) then
      return nil, "addr_len"
    end
    out[#out + 1] = raw
  end
  return out, nil
end
local encode_verdict
encode_verdict = function(client_ip, txid, qname, override)
  if not (client_ip and override) then
    return nil
  end
  local code = _KIND_TO_CODE[override.kind]
  if not (code) then
    return nil
  end
  local ttl = tonumber(override.ttl)
  local line = concat({
    VERDICT_PREFIX,
    code,
    tostring(client_ip),
    string.format("%04x", tonumber(txid) or 0),
    tostring(ttl and math.floor(ttl) or -1),
    to_hex(tostring(qname or "")),
    to_hex(tostring(override.cname_target or "")),
    _encode_addrs(override.a),
    _encode_addrs(override.aaaa)
  }, "|")
  if #line > MAX_VERDICT_LINE then
    return nil
  end
  return line .. "\n"
end
local decode_verdict
decode_verdict = function(line)
  local s = (tostring(line)):gsub("\n+$", "")
  local parts = split_fields(s)
  if not (#parts == 9) then
    return nil, "field_count"
  end
  if not (parts[1] == VERDICT_PREFIX) then
    return nil, "version"
  end
  local kind = _CODE_TO_KIND[parts[2]]
  if not (kind) then
    return nil, "kind"
  end
  local client_ip = parts[3]
  if not (is_ipv4_str(client_ip) or is_ipv6_str(client_ip)) then
    return nil, "client_ip"
  end
  local txid = tonumber(parts[4], 16)
  if not (txid and txid >= 0 and txid <= 65535) then
    return nil, "txid"
  end
  local ttl = tonumber(parts[5])
  if not (ttl) then
    return nil, "ttl"
  end
  local qname, e1 = from_hex(parts[6])
  if e1 then
    return nil, "qname_" .. tostring(e1)
  end
  local cname, e2 = from_hex(parts[7])
  if e2 then
    return nil, "cname_" .. tostring(e2)
  end
  local a, e3 = _decode_addrs(parts[8], 4)
  if e3 then
    return nil, "a_" .. tostring(e3)
  end
  local aaaa, e4 = _decode_addrs(parts[9], 16)
  if e4 then
    return nil, "aaaa_" .. tostring(e4)
  end
  return {
    client_ip = client_ip,
    txid = txid,
    qname = qname or "",
    override = {
      kind = kind,
      a = a,
      aaaa = aaaa,
      ttl = (ttl >= 0 and ttl or nil),
      cname_target = (cname and cname ~= "") and cname or nil
    }
  }, nil
end
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
  local purge_verdicts
  purge_verdicts = function(now_s)
    for key, e in pairs(verdicts) do
      if now_s > e.expires_at then
        verdicts[key] = nil
      end
    end
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
    purge_verdicts = purge_verdicts,
    budget_ms = budget_ms
  }
end
return {
  new = new,
  encode_verdict = encode_verdict,
  decode_verdict = decode_verdict,
  VERDICT_PREFIX = VERDICT_PREFIX,
  MAX_VERDICT_LINE = MAX_VERDICT_LINE
}
