local dns_mod = require("ipparse.l7.dns")
local sp = require("ipparse.lib.pack_compat").pack
local QTYPE_A = dns_mod.types.A
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
make_dns_payload = function(with_https)
  if with_https == nil then
    with_https = false
  end
  local question = qname_example .. sp(">H H", QTYPE_A, QCLASS_IN)
  local answer_a = pack_rr(QTYPE_A, string.char(1, 2, 3, 4))
  if with_https then
    local answer_https = pack_rr(QTYPE_HTTPS, "\0\1")
    local header = sp(">H H H H H H", 0x1234, 0x8180, 1, 2, 0, 0)
    return header .. question .. answer_a .. answer_https
  end
  local header = sp(">H H H H H H", 0x1234, 0x8180, 1, 1, 0, 0)
  return header .. question .. answer_a
end
local fresh_worker_responses
fresh_worker_responses = function()
  package.loaded["worker_responses"] = nil
  return dofile("lua/worker_responses.lua")
end
return describe("worker_responses helpers", function()
  before_each(function()
    local config = require("config")
    config.dns = {
      ttl_grace = {
        grace = 0,
        min = 60,
        max = 900
      }
    }
  end)
  it("rr_timeout borne TTL + grace", function()
    local m = fresh_worker_responses()
    local config = require("config")
    config.dns.ttl_grace.grace = 0
    local _, ttl_min = m.rr_timeout(0)
    assert.equals(60, ttl_min)
    assert.equals("60s", (m.rr_timeout(0)))
    config.dns.ttl_grace.grace = 120
    local ttl_mid
    _, ttl_mid = m.rr_timeout(60)
    assert.equals(180, ttl_mid)
    local ttl_max
    _, ttl_max = m.rr_timeout(5000)
    return assert.equals(900, ttl_max)
  end)
  it("bench_delta ignore les jalons absents ou négatifs", function()
    local m = fresh_worker_responses()
    assert.equals(7, m.bench_delta(17, 10))
    assert.is_nil(m.bench_delta(nil, 10))
    assert.is_nil(m.bench_delta(10, nil))
    return assert.is_nil(m.bench_delta(10, 17))
  end)
  it("patch_modified_dns n'ajoute EDE que si le payload change", function()
    local m = fresh_worker_responses()
    local clean = make_dns_payload(false)
    local patched_clean, modified_clean = m.patch_modified_dns(clean, "policy")
    assert.equals(clean, patched_clean)
    assert.is_false(modified_clean)
    assert.is_nil(patched_clean:find("Custos vigilat", 1, true))
    local modified = make_dns_payload(true)
    local patched_modified, modified_flag = m.patch_modified_dns(modified, "policy")
    assert.is_true(modified_flag)
    return assert.is_not_nil(patched_modified:find("Custos vigilat%. policy", 1))
  end)
  return it("patch_modified_dns efface le bit AD quand HTTPS/SVCB sont stripés", function()
    local m = fresh_worker_responses()
    local bit = require("bit")
    local question = qname_example .. sp(">H H", QTYPE_A, QCLASS_IN)
    local answer_a = pack_rr(QTYPE_A, string.char(1, 2, 3, 4))
    local answer_https = pack_rr(QTYPE_HTTPS, "\0\1")
    local header_with_ad = sp(">H H H H H H", 0x1234, 0x8520, 1, 2, 0, 0)
    local raw_with_https_and_ad = header_with_ad .. question .. answer_a .. answer_https
    local patched, modified = m.patch_modified_dns(raw_with_https_and_ad, "test")
    assert.is_true(modified)
    local flags_after = patched:byte(3) * 256 + patched:byte(4)
    assert.equals(0x8500, flags_after)
    local parsed = dns_mod.parse(patched, 1, false)
    assert.equals(1, #parsed.answers)
    return assert.equals(QTYPE_A, parsed.answers[1].rtype)
  end)
end)
