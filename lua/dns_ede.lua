local dns_mod = require("ipparse.l7.dns")
local parse = dns_mod.parse
local REFUSED = dns_mod.rcodes.REFUSED
local A = dns_mod.types.A
local AAAA = dns_mod.types.AAAA
local ede_codes = dns_mod.ede_codes
local sp
sp = require("ipparse.lib.pack_compat").pack
local insert, remove
do
  local _obj_0 = table
  insert, remove = _obj_0.insert, _obj_0.remove
end
local EDE_BLOCKED = ede_codes.Filtered
local EDE_TTL_MODIFIED = ede_codes.Forged_Answer
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
    rclass = 0,
    ttl = 0,
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
      ttl = 60,
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
local add_ede_ttl
add_ede_ttl = function(dns_payload, reason)
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
return {
  add_ede = add_ede,
  build_blocked_response = build_blocked_response,
  add_ede_ttl = add_ede_ttl,
  EDE_BLOCKED = EDE_BLOCKED,
  EDE_TTL_MODIFIED = EDE_TTL_MODIFIED
}
