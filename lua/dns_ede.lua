local dns_mod = require("ipparse.l7.dns")
local parse = dns_mod.parse
local REFUSED = dns_mod.rcodes.REFUSED
local NXDOMAIN = dns_mod.rcodes.NXDOMAIN
local A = dns_mod.types.A
local AAAA = dns_mod.types.AAAA
local HTTPS = dns_mod.types.HTTPS
local SVCB = dns_mod.types.SVCB
local ede_codes = dns_mod.ede_codes
local sp
sp = require("ipparse.lib.pack_compat").pack
local bit = require("bit")
local insert, remove
do
  local _obj_0 = table
  insert, remove = _obj_0.insert, _obj_0.remove
end
local EDE_BLOCKED = ede_codes.Filtered
local EDE_TTL_MODIFIED = ede_codes.Forged_Answer
local DNS_FLAG_AD = 0x0020
local add_ede
add_ede = function(dns, code, text)
  for i = #(dns.additionals or { }), 1, -1 do
    if dns.additionals[i].rtype == 0x29 then
      remove(dns.additionals, i)
    end
  end
  dns.additionals = dns.additionals or { }
  insert(dns.additionals, 1, {
    rname = "\0",
    rtype = 0x29,
    rdata = sp(">Hs2", 0x000F, (sp(">H", code) .. text))
  })
  dns.header.arcount = #dns.additionals
  return dns
end
local build_blocked_response
build_blocked_response = function(dns_orig, dns_raw, reason)
  if not (dns_orig and dns_raw) then
    return nil
  end
  local dns = parse(dns_raw, 1, false)
  if not (dns) then
    return nil
  end
  dns.header.rcode = REFUSED
  dns.answers = { }
  if dns.question and dns.question.qtype then
    local qtype = dns.question.qtype
    local rdata
    if qtype == A then
      rdata = string.char(0, 0, 0, 0)
    elseif qtype == AAAA then
      rdata = string.char(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    else
      rdata = string.char(0, 0, 0, 0)
    end
    dns.answers[1] = {
      rname = string.char(0xC0, 0x0C),
      rtype = qtype,
      rclass = 1,
      rdata = rdata
    }
    dns.header.ancount = 1
  end
  local ede_text
  if reason and reason ~= "" then
    ede_text = "Ne intretis. " .. reason
  else
    ede_text = "Ne intretis."
  end
  add_ede(dns, EDE_BLOCKED, ede_text)
  return tostring(dns)
end
local build_nxdomain_response
build_nxdomain_response = function(dns_orig, dns_raw, reason)
  if not (dns_orig and dns_raw) then
    return nil
  end
  local dns = parse(dns_raw, 1, false)
  if not (dns) then
    return nil
  end
  dns.header.rcode = NXDOMAIN
  dns.answers = { }
  dns.header.ancount = 0
  local ede_text
  if reason and reason ~= "" then
    ede_text = "Ne intretis. " .. reason
  else
    ede_text = "Ne intretis."
  end
  add_ede(dns, EDE_BLOCKED, ede_text)
  return tostring(dns)
end
local add_ede_modified
add_ede_modified = function(dns_payload, reason)
  local dns = parse(dns_payload, 1, false)
  if not (dns) then
    return dns_payload
  end
  local ede_text
  if reason and reason ~= "" then
    ede_text = "Custos vigilat. " .. reason
  else
    ede_text = "Custos vigilat."
  end
  add_ede(dns, EDE_TTL_MODIFIED, ede_text)
  return tostring(dns)
end
local strip_rrtypes
strip_rrtypes = function(dns_payload, rrtypes)
  if not (dns_payload and #dns_payload >= 12) then
    return dns_payload
  end
  local len = #dns_payload
  local u16
  u16 = function(off)
    if off + 1 > len then
      return nil
    end
    return dns_payload:byte(off) * 256 + dns_payload:byte(off + 1)
  end
  local skip_name
  skip_name = function(off)
    local cur = off
    local steps = 0
    while cur <= len do
      steps = steps + 1
      if steps > 128 then
        return nil
      end
      local b = dns_payload:byte(cur)
      if not (b) then
        return nil
      end
      if b == 0 then
        return cur + 1
      elseif b >= 0xC0 then
        if cur + 1 > len then
          return nil
        end
        return cur + 2
      else
        if cur + b > len then
          return nil
        end
        cur = cur + (1 + b)
      end
    end
    return nil
  end
  local id = u16(1)
  local flags = u16(3)
  local qdcount = u16(5)
  local ancount = u16(7)
  local nscount = u16(9)
  local arcount = u16(11)
  if not (id and flags and qdcount and ancount and nscount and arcount) then
    return dns_payload
  end
  local off = 13
  local question_parts = { }
  for i = 1, qdcount do
    local q_end = skip_name(off)
    if not (q_end) then
      return dns_payload
    end
    if q_end + 3 > len then
      return dns_payload
    end
    question_parts[#question_parts + 1] = dns_payload:sub(off, q_end + 3)
    off = q_end + 4
  end
  local copy_section
  copy_section = function(count)
    local kept = 0
    local sec = { }
    for i = 1, count do
      local rr_start = off
      local name_end = skip_name(off)
      if not (name_end) then
        return nil
      end
      if name_end + 9 > len then
        return nil
      end
      local rrtype = u16(name_end)
      local rdlength = u16(name_end + 8)
      local rr_end = name_end + 10 + rdlength - 1
      if rr_end > len then
        return nil
      end
      if not rrtypes[rrtype] then
        sec[#sec + 1] = dns_payload:sub(rr_start, rr_end)
        kept = kept + 1
      end
      off = rr_end + 1
    end
    return kept, table.concat(sec)
  end
  local ancount_new, answers = copy_section(ancount)
  if not (answers) then
    return dns_payload
  end
  local nscount_new, authorities = copy_section(nscount)
  if not (authorities) then
    return dns_payload
  end
  local arcount_new, additionals = copy_section(arcount)
  if not (additionals) then
    return dns_payload
  end
  local header = sp(">H H H H H H", id, flags, qdcount, ancount_new, nscount_new, arcount_new)
  return header .. table.concat(question_parts) .. answers .. authorities .. additionals
end
local strip_dns_rr
strip_dns_rr = function(dns_payload, rtype)
  local resolve
  resolve = function(t)
    if type(t) == "number" then
      return t
    end
    local v = dns_mod.types[t]
    if not (v) then
      error("strip_dns_rr : type DNS inconnu '" .. tostring(t) .. "'")
    end
    return v
  end
  local set = { }
  if type(rtype) == "table" then
    for _index_0 = 1, #rtype do
      local t = rtype[_index_0]
      set[resolve(t)] = true
    end
  else
    set[resolve(rtype)] = true
  end
  return strip_rrtypes(dns_payload, set)
end
local strip_a_rr
strip_a_rr = function(p)
  return strip_dns_rr(p, A)
end
local strip_aaaa_rr
strip_aaaa_rr = function(p)
  return strip_dns_rr(p, AAAA)
end
local strip_https_rr
strip_https_rr = function(p)
  return strip_dns_rr(p, {
    HTTPS,
    SVCB
  })
end
local clear_ad_bit
clear_ad_bit = function(dns_payload)
  if not (dns_payload and #dns_payload >= 4) then
    return dns_payload
  end
  local flags = dns_payload:byte(3) * 256 + dns_payload:byte(4)
  local flags_new = bit.band(flags, bit.bnot(DNS_FLAG_AD))
  if flags_new == flags then
    return dns_payload
  end
  return dns_payload:sub(1, 2) .. string.char(bit.rshift(flags_new, 8)) .. string.char(bit.band(flags_new, 0xFF)) .. dns_payload:sub(5)
end
return {
  add_ede = add_ede,
  build_blocked_response = build_blocked_response,
  build_nxdomain_response = build_nxdomain_response,
  add_ede_modified = add_ede_modified,
  strip_dns_rr = strip_dns_rr,
  strip_https_rr = strip_https_rr,
  strip_a_rr = strip_a_rr,
  strip_aaaa_rr = strip_aaaa_rr,
  clear_ad_bit = clear_ad_bit,
  EDE_BLOCKED = EDE_BLOCKED,
  EDE_TTL_MODIFIED = EDE_TTL_MODIFIED
}
