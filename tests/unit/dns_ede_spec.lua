package.path = "src/?.lua;src/?/init.lua;src/?/?.lua;lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path
local strip_https_rr, strip_a_rr, strip_aaaa_rr, add_ede_modified, clear_ad_bit, build_cname_response
do
  local _obj_0 = require("dns_ede")
  strip_https_rr, strip_a_rr, strip_aaaa_rr, add_ede_modified, clear_ad_bit, build_cname_response = _obj_0.strip_https_rr, _obj_0.strip_a_rr, _obj_0.strip_aaaa_rr, _obj_0.add_ede_modified, _obj_0.clear_ad_bit, _obj_0.build_cname_response
end
local encode_dns_name
encode_dns_name = require("lib.dns_name").encode_dns_name
local dns_mod = require("ipparse.l7.dns")
local sp
sp = require("ipparse.lib.pack_compat").pack
local bit = require("bit")
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
describe("dns_ede.strip_https_rr", function()
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
describe("dns_ede.add_ede_modified", function()
  return it("ajoute un OPT/EDE code 4 avec texte Custos vigilat", function()
    local question = qname_example .. sp(">H H", QTYPE_A, QCLASS_IN)
    local answer_a = pack_rr(QTYPE_A, string.char(9, 9, 9, 9))
    local header = sp(">H H H H H H", 0xBEEF, 0x8180, 1, 1, 0, 0)
    local raw = header .. question .. answer_a
    local patched = add_ede_modified(raw, "policy")
    local parsed = dns_mod.parse(patched, 1, false)
    assert.is_not_nil(parsed)
    assert.equals(1, #parsed.additionals)
    assert.equals(0x29, parsed.additionals[1].rtype)
    return assert.is_true(patched:find("Custos vigilat%. policy", 1) ~= nil)
  end)
end)
describe("dns_ede.clear_ad_bit", function()
  it("efface le bit AD (0x0020) dans le champ flags", function()
    local question = qname_example .. sp(">H H", QTYPE_A, QCLASS_IN)
    local answer_a = pack_rr(QTYPE_A, string.char(10, 10, 10, 10))
    local header = sp(">H H H H H H", 0xBEEF, 0x8520, 1, 1, 0, 0)
    local raw = header .. question .. answer_a
    local cleared = clear_ad_bit(raw)
    assert.is_not_nil(cleared)
    assert.equals(raw:byte(1), cleared:byte(1))
    local flags_cleared = cleared:byte(3) * 256 + cleared:byte(4)
    return assert.equals(0x8500, flags_cleared)
  end)
  return it("laisse inchangé un payload sans bit AD", function()
    local question = qname_example .. sp(">H H", QTYPE_A, QCLASS_IN)
    local answer_a = pack_rr(QTYPE_A, string.char(11, 11, 11, 11))
    local header = sp(">H H H H H H", 0xABCD, 0x8180, 1, 1, 0, 0)
    local raw = header .. question .. answer_a
    local cleared = clear_ad_bit(raw)
    return assert.equals(raw, cleared)
  end)
end)
describe("dns_ede.strip_a_rr", function()
  it("retire les RR A (IPv4) de la section answers", function()
    local question = qname_example .. sp(">H H", QTYPE_A, QCLASS_IN)
    local answer_a1 = pack_rr(QTYPE_A, string.char(1, 2, 3, 4))
    local answer_a2 = pack_rr(QTYPE_A, string.char(5, 6, 7, 8))
    local header = sp(">H H H H H H", 0x1234, 0x8180, 1, 2, 0, 0)
    local raw = header .. question .. answer_a1 .. answer_a2
    local stripped = strip_a_rr(raw)
    local parsed_after = dns_mod.parse(stripped, 1, false)
    assert.is_not_nil(parsed_after)
    return assert.equals(0, #parsed_after.answers)
  end)
  it("retire seulement les RR A, conserve les autres types", function()
    local question = qname_example .. sp(">H H", QTYPE_A, QCLASS_IN)
    local answer_a = pack_rr(QTYPE_A, string.char(1, 2, 3, 4))
    local answer_aaaa = pack_rr(dns_mod.types.AAAA, string.char(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1))
    local header = sp(">H H H H H H", 0x2345, 0x8180, 1, 2, 0, 0)
    local raw = header .. question .. answer_a .. answer_aaaa
    local stripped = strip_a_rr(raw)
    local parsed_after = dns_mod.parse(stripped, 1, false)
    assert.is_not_nil(parsed_after)
    assert.equals(1, #parsed_after.answers)
    return assert.equals(dns_mod.types.AAAA, parsed_after.answers[1].rtype)
  end)
  return it("laisse inchangé un payload sans RR A", function()
    local question = qname_example .. sp(">H H", QTYPE_A, QCLASS_IN)
    local answer_aaaa = pack_rr(dns_mod.types.AAAA, string.char(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1))
    local header = sp(">H H H H H H", 0x4321, 0x8180, 1, 1, 0, 0)
    local raw = header .. question .. answer_aaaa
    return assert.equals(raw, strip_a_rr(raw))
  end)
end)
describe("dns_ede.strip_aaaa_rr", function()
  it("retire les RR AAAA (IPv6) de la section answers", function()
    local question = qname_example .. sp(">H H", QTYPE_A, QCLASS_IN)
    local answer_aaaa1 = pack_rr(dns_mod.types.AAAA, string.char(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1))
    local answer_aaaa2 = pack_rr(dns_mod.types.AAAA, string.char(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2))
    local header = sp(">H H H H H H", 0x1234, 0x8180, 1, 2, 0, 0)
    local raw = header .. question .. answer_aaaa1 .. answer_aaaa2
    local stripped = strip_aaaa_rr(raw)
    local parsed_after = dns_mod.parse(stripped, 1, false)
    assert.is_not_nil(parsed_after)
    return assert.equals(0, #parsed_after.answers)
  end)
  it("retire seulement les RR AAAA, conserve les autres types", function()
    local question = qname_example .. sp(">H H", QTYPE_A, QCLASS_IN)
    local answer_a = pack_rr(QTYPE_A, string.char(1, 2, 3, 4))
    local answer_aaaa = pack_rr(dns_mod.types.AAAA, string.char(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1))
    local header = sp(">H H H H H H", 0x2345, 0x8180, 1, 2, 0, 0)
    local raw = header .. question .. answer_a .. answer_aaaa
    local stripped = strip_aaaa_rr(raw)
    local parsed_after = dns_mod.parse(stripped, 1, false)
    assert.is_not_nil(parsed_after)
    assert.equals(1, #parsed_after.answers)
    return assert.equals(QTYPE_A, parsed_after.answers[1].rtype)
  end)
  return it("laisse inchangé un payload sans RR AAAA", function()
    local question = qname_example .. sp(">H H", QTYPE_A, QCLASS_IN)
    local answer_a = pack_rr(QTYPE_A, string.char(1, 2, 3, 4))
    local header = sp(">H H H H H H", 0x4321, 0x8180, 1, 1, 0, 0)
    local raw = header .. question .. answer_a
    return assert.equals(raw, strip_aaaa_rr(raw))
  end)
end)
return describe("build_cname_response", function()
  local CNAME = dns_mod.types.CNAME
  local get_rcode
  get_rcode = function(raw)
    return bit.band(raw:byte(4), 0x0f)
  end
  local decode_name
  decode_name = function(rdata)
    local labels, i = { }, 1
    while i <= #rdata do
      local l = rdata:byte(i)
      if l == 0 then
        break
      end
      labels[#labels + 1] = rdata:sub(i + 1, i + l)
      i = i + (l + 1)
    end
    return table.concat(labels, ".")
  end
  local make_query
  make_query = function(qtype)
    if qtype == nil then
      qtype = QTYPE_A
    end
    local q = dns_mod.new({
      header = dns_mod.new_header({
        id = 0x1234,
        rd = true
      }),
      questions = {
        {
          qname = encode_dns_name("www.google.com"),
          qtype = qtype,
          qclass = QCLASS_IN
        }
      }
    })
    return tostring(q)
  end
  it("produit une réponse NOERROR avec un unique RR CNAME vers la cible", function()
    local resp = build_cname_response(nil, make_query(), "forcesafesearch.google.com", "SafeSearch")
    assert.is_not_nil(resp)
    assert.equals(0, get_rcode(resp))
    local parsed = dns_mod.parse(resp, 1, false)
    assert.equals(1, parsed.header.ancount)
    assert.equals(CNAME, parsed.answers[1].rtype)
    return assert.equals("forcesafesearch.google.com", decode_name(parsed.answers[1].rdata))
  end)
  it("fonctionne quel que soit le qtype de la question (ex: AAAA)", function()
    local resp = build_cname_response(nil, make_query(dns_mod.types.AAAA), "restrict.youtube.com", nil)
    local parsed = dns_mod.parse(resp, 1, false)
    return assert.equals(CNAME, parsed.answers[1].rtype)
  end)
  it("renvoie nil si dns_raw absent ou cible vide", function()
    assert.is_nil(build_cname_response(nil, nil, "x.example", nil))
    return assert.is_nil(build_cname_response(nil, make_query(), "", nil))
  end)
  return it("marque la réponse d'une EDE (OPT RR présent dans additionals)", function()
    local resp = build_cname_response(nil, make_query(), "safe.duckduckgo.com", "x")
    local parsed = dns_mod.parse(resp, 1, false)
    local has_opt = false
    local _list_0 = (parsed.additionals or { })
    for _index_0 = 1, #_list_0 do
      local rr = _list_0[_index_0]
      if rr.rtype == 0x29 then
        has_opt = true
      end
    end
    return assert.is_true(has_opt)
  end)
end)
