dns_mod = require "ipparse.l7.dns"
sp = require("ipparse.lib.pack_compat").pack

QTYPE_A = dns_mod.types.A
QTYPE_HTTPS = dns_mod.types.HTTPS
QCLASS_IN = dns_mod.classes.IN
qname_example = "\7example\3com\0"
name_ptr = "\192\012"

pack_rr = (rtype, rdata, ttl=60) ->
  name_ptr .. sp(">H H I4 s2", rtype, QCLASS_IN, ttl, rdata)

make_dns_payload = (with_https=false) ->
  question = qname_example .. sp(">H H", QTYPE_A, QCLASS_IN)
  answer_a = pack_rr QTYPE_A, string.char(1, 2, 3, 4)
  if with_https
    answer_https = pack_rr QTYPE_HTTPS, "\0\1"
    header = sp ">H H H H H H", 0x1234, 0x8180, 1, 2, 0, 0
    return header .. question .. answer_a .. answer_https
  header = sp ">H H H H H H", 0x1234, 0x8180, 1, 1, 0, 0
  header .. question .. answer_a

fresh_worker_responses = ->
  package.loaded["worker_responses"] = nil
  dofile "lua/worker_responses.lua"

describe "worker_responses helpers", ->
  before_each ->
    config = require "config"
    config.dns = {
      ttl_grace: {
        grace: 0
        min: 60
        max: 900
      }
    }

  it "rr_timeout borne TTL + grace", ->
    m = fresh_worker_responses!
    config = require "config"

    config.dns.ttl_grace.grace = 0
    _, ttl_min = m.rr_timeout 0
    assert.equals 60, ttl_min
    assert.equals "60s", (m.rr_timeout 0)

    config.dns.ttl_grace.grace = 120
    _, ttl_mid = m.rr_timeout 60
    assert.equals 180, ttl_mid

    _, ttl_max = m.rr_timeout 5000
    assert.equals 900, ttl_max

  it "patch_modified_dns n'ajoute EDE que si le payload change", ->
    m = fresh_worker_responses!
    clean = make_dns_payload false
    patched_clean, modified_clean = m.patch_modified_dns clean, "policy"
    assert.equals clean, patched_clean
    assert.is_false modified_clean
    assert.is_nil patched_clean\find("Custos vigilat", 1, true)

    modified = make_dns_payload true
    patched_modified, modified_flag = m.patch_modified_dns modified, "policy"
    assert.is_true modified_flag
    assert.is_not_nil patched_modified\find("Custos vigilat%. policy", 1)
