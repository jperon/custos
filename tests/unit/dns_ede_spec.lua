local strip_https_rr
strip_https_rr = require("dns_ede").strip_https_rr
local dns_mod = require("ipparse.l7.dns")
local sp
sp = require("ipparse.lib.pack_compat").pack
local QTYPE_A = dns_mod.types.A
local QTYPE_SVCB = dns_mod.types.SVCB
local QTYPE_HTTPS = dns_mod.types.HTTPS
local QCLASS_IN = dns_mod.classes.IN
local qname_example = "\7example\3com\0"
local name_ptr = "\192\012"
local pack_rr
pack_rr = function(rtype, rdata, ttl)
  if ttl == nil then
    ttl = 60
  end
  return name_ptr .. sp(">H H I4 s2", rtype, QCLASS_IN, ttl, rdata)
end
local make_dns_payload
make_dns_payload = function()
  local question = qname_example .. sp(">H H", QTYPE_A, QCLASS_IN)
  local answer_a = pack_rr(QTYPE_A, string.char(1, 2, 3, 4))
  local answer_https = pack_rr(QTYPE_HTTPS, "\0\1")
  local authority_https = pack_rr(QTYPE_HTTPS, "\0\2")
  local additional_https = pack_rr(QTYPE_HTTPS, "\0\3")
  local header = sp(">H H H H H H", 0x1234, 0x8180, 1, 2, 1, 1)
  return header .. question .. answer_a .. answer_https .. authority_https .. additional_https
end
return describe("dns_ede.strip_https_rr", function()
  it("retire les RR HTTPS (type 65) et SVCB (type 64) de toutes les sections", function()
    local raw = make_dns_payload()
    local parsed_before = dns_mod.parse(raw, 1, false)
    assert.is_not_nil(parsed_before)
    assert.equals(2, #parsed_before.answers)
    assert.equals(1, #parsed_before.authorities)
    assert.equals(1, #parsed_before.additionals)
    local stripped = strip_https_rr(raw)
    local parsed_after = dns_mod.parse(stripped, 1, false)
    assert.is_not_nil(parsed_after)
    assert.equals(1, #parsed_after.answers)
    assert.equals(0, #parsed_after.authorities)
    assert.equals(0, #parsed_after.additionals)
    return assert.equals(QTYPE_A, parsed_after.answers[1].rtype)
  end)
  it("retire aussi les RR SVCB", function()
    local question = qname_example .. sp(">H H", QTYPE_A, QCLASS_IN)
    local answer_a = pack_rr(QTYPE_A, string.char(1, 1, 1, 1))
    local answer_svcb = pack_rr(QTYPE_SVCB, "\0\1")
    local authority_svcb = pack_rr(QTYPE_SVCB, "\0\2")
    local additional_svcb = pack_rr(QTYPE_SVCB, "\0\3")
    local header = sp(">H H H H H H", 0x2345, 0x8180, 1, 2, 1, 1)
    local raw = header .. question .. answer_a .. answer_svcb .. authority_svcb .. additional_svcb
    local stripped = strip_https_rr(raw)
    local parsed_after = dns_mod.parse(stripped, 1, false)
    assert.is_not_nil(parsed_after)
    assert.equals(1, #parsed_after.answers)
    assert.equals(0, #parsed_after.authorities)
    assert.equals(0, #parsed_after.additionals)
    return assert.equals(QTYPE_A, parsed_after.answers[1].rtype)
  end)
  return it("laisse inchangé un payload sans RR HTTPS", function()
    local question = qname_example .. sp(">H H", QTYPE_A, QCLASS_IN)
    local answer_a = pack_rr(QTYPE_A, string.char(8, 8, 8, 8))
    local header = sp(">H H H H H H", 0x4321, 0x8180, 1, 1, 0, 0)
    local raw = header .. question .. answer_a
    return assert.equals(raw, strip_https_rr(raw))
  end)
end)
