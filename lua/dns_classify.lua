local dns_mod = require("ipparse.l7.dns")
local labels, types
labels, types = dns_mod.labels, dns_mod.types
local concat
concat = table.concat
local bit = require("bit")
local CNAME = types.CNAME
local A = types.A
local AAAA = types.AAAA
local NXDOMAIN = dns_mod.rcodes.NXDOMAIN
local numeric_rcode
numeric_rcode = function(header)
  return bit.band((header and header.ra_z_rcode or 0), 0x0f)
end
local decode_cname_target
decode_cname_target = function(rr, raw, l7_off)
  if l7_off == nil then
    l7_off = 1
  end
  if not (rr and rr.rdata and rr.end_off and raw) then
    return nil
  end
  local rdata_start = rr.end_off - #rr.rdata + 1
  if rdata_start < 1 then
    return nil
  end
  local lbls = labels(raw, rdata_start, l7_off)
  if not (lbls and #lbls > 0) then
    return nil
  end
  return concat(lbls, "."):lower()
end
local cname_targets
cname_targets = function(dns, raw, l7_off)
  if l7_off == nil then
    l7_off = 1
  end
  local out = { }
  local _list_0 = (dns and dns.answers or { })
  for _index_0 = 1, #_list_0 do
    local rr = _list_0[_index_0]
    if rr.rtype == CNAME then
      do
        local target = decode_cname_target(rr, raw, l7_off)
        if target then
          out[#out + 1] = target
        end
      end
    end
  end
  return out
end
local has_cname_target
has_cname_target = function(dns, raw, target, l7_off)
  if l7_off == nil then
    l7_off = 1
  end
  if not (target and target ~= "") then
    return false
  end
  local want = target:lower()
  local _list_0 = cname_targets(dns, raw, l7_off)
  for _index_0 = 1, #_list_0 do
    local t = _list_0[_index_0]
    if t == want then
      return true
    end
  end
  return false
end
local is_sinkhole_addr
is_sinkhole_addr = function(rdata)
  if not (rdata and (#rdata == 4 or #rdata == 16)) then
    return false
  end
  for i = 1, #rdata do
    if rdata:byte(i) ~= 0 then
      return false
    end
  end
  return true
end
local is_sinkhole
is_sinkhole = function(dns)
  local seen = false
  local _list_0 = (dns and dns.answers or { })
  for _index_0 = 1, #_list_0 do
    local rr = _list_0[_index_0]
    if rr.rtype == A or rr.rtype == AAAA then
      if not (is_sinkhole_addr(rr.rdata)) then
        return false
      end
      seen = true
    end
  end
  return seen
end
local classify
classify = function(dns, raw, l7_off)
  if l7_off == nil then
    l7_off = 1
  end
  if not (dns and dns.header) then
    return {
      verdict = "pass"
    }
  end
  if numeric_rcode(dns.header) == NXDOMAIN then
    return {
      verdict = "block"
    }
  end
  local a, aaaa, ttl = { }, { }, nil
  local _list_0 = (dns.answers or { })
  for _index_0 = 1, #_list_0 do
    local rr = _list_0[_index_0]
    if rr.rtype == A and rr.rdata and #rr.rdata == 4 then
      a[#a + 1] = rr.rdata
    elseif rr.rtype == AAAA and rr.rdata and #rr.rdata == 16 then
      aaaa[#aaaa + 1] = rr.rdata
    end
    if rr.ttl and (not ttl or rr.ttl < ttl) then
      ttl = rr.ttl
    end
  end
  if is_sinkhole(dns) then
    return {
      verdict = "sinkhole",
      a = a,
      aaaa = aaaa,
      ttl = ttl
    }
  end
  local targets = cname_targets(dns, raw, l7_off)
  if #targets == 0 then
    return {
      verdict = "pass"
    }
  end
  return {
    verdict = "redirect",
    cname_target = targets[#targets],
    a = a,
    aaaa = aaaa,
    ttl = ttl
  }
end
return {
  classify = classify,
  cname_targets = cname_targets,
  has_cname_target = has_cname_target,
  decode_cname_target = decode_cname_target,
  numeric_rcode = numeric_rcode,
  is_sinkhole = is_sinkhole,
  is_sinkhole_addr = is_sinkhole_addr
}
