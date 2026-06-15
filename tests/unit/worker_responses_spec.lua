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
describe("worker_responses helpers", function()
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
  it("patch_modified_dns efface le bit AD quand HTTPS/SVCB sont stripés", function()
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
  describe("build_benchmark_fields", function()
    local info = {
      client_mac = "aa:bb:cc:dd:ee:ff",
      vlan = 8,
      client_ip = "10.35.8.2",
      resolver_ip = "1.1.1.1",
      client_port = 5353,
      txid = 0x1f4d,
      af = "ipv4",
      user = "alice@lan",
      qname = "example.com",
      qtype = "A",
      retry_wait_ms = 3,
      retry_attempts = 1
    }
    local deltas = {
      delta_ms = 12,
      question_proc_ms = 4,
      response_entry_ms = 5,
      drain_ms = 0,
      payload_ms = 1,
      parse_ms = 2,
      match_ms = 0,
      log_ms = 0
    }
    it("verdict allow quand entry.refused est faux", function()
      local m = fresh_worker_responses()
      local entry = {
        refused = false,
        reason = "Allowed by rule: X",
        rule_id = "r_ok",
        dnsonly = false
      }
      local fields, verdict = m.build_benchmark_fields(entry, info, deltas)
      assert.equals("allow", verdict)
      assert.equals("dns_benchmark", fields.action)
      assert.equals("r_ok", fields.rule)
      assert.equals("example.com", fields.qname)
      assert.equals("A", fields.qtype)
      assert.equals("10.35.8.2", fields.src_ip)
      assert.equals("1.1.1.1", fields.dst_ip)
      assert.equals(12, fields.q_to_response_ms)
      assert.is_nil(fields.delta_ms)
      assert.equals(4, fields.question_proc_ms)
      assert.equals(5, fields.response_entry_ms)
      assert.equals(2, fields.parse_ms)
      return assert.equals("0x1f4d", fields.txid)
    end)
    return it("verdict block quand entry.refused est vrai", function()
      local m = fresh_worker_responses()
      local entry = {
        refused = true,
        reason = "default deny",
        rule_id = "default_deny",
        dnsonly = false
      }
      local fields, verdict = m.build_benchmark_fields(entry, info, deltas)
      assert.equals("block", verdict)
      return assert.equals("default_deny", fields.rule)
    end)
  end)
  return describe("format_block_event (blocage validateur amont)", function()
    local ctx = {
      qname = "emergent.sh",
      client_mac = "e0:8f:4c:c8:91:fa",
      src_ip = "10.35.99.38",
      dst_ip = "1.1.1.3",
      vlan = 99,
      user = "j@prn.ovh",
      af = "ipv4",
      nft_rule_id = "r_utilisateurs"
    }
    it("produit une ligne TSV block au format de worker_events", function()
      local m = fresh_worker_responses()
      local line = m.format_block_event(ctx, 1781382351)
      return assert.equals("1781382351\tblock\temergent.sh\te0:8f:4c:c8:91:fa\t10.35.99.38\t1.1.1.3\t99\tj@prn.ovh\tipv4\tFiltered by upstream validator\tr_utilisateurs\n", line)
    end)
    it("remplace les champs vides par '-' (compatible tsv_field)", function()
      local m = fresh_worker_responses()
      local line = m.format_block_event({
        qname = "x.com"
      }, 100)
      local fields
      do
        local _accum_0 = { }
        local _len_0 = 1
        for f in line:gsub("\n", ""):gmatch("[^\t]+") do
          _accum_0[_len_0] = f
          _len_0 = _len_0 + 1
        end
        fields = _accum_0
      end
      assert.equals("block", fields[2])
      assert.equals("x.com", fields[3])
      assert.equals("-", fields[4])
      return assert.equals("Filtered by upstream validator", fields[10])
    end)
    return it("la décision est bien 'block' et exploitable par worker_events.process_line", function()
      local m = fresh_worker_responses()
      local we = require("worker_events")
      local line = m.format_block_event(ctx, 1781382351)
      local recent = { }
      assert.is_true(we.process_line(line:gsub("\n", ""), { }, recent))
      assert.equals("emergent.sh", recent[1].qname)
      return assert.equals("e0:8f:4c:c8:91:fa", recent[1].mac)
    end)
  end)
end)
return describe("worker_responses upstream retry", function()
  local parse_ip, s2ip
  do
    local _obj_0 = require("ipparse.l3.ip")
    parse_ip, s2ip = _obj_0.parse, _obj_0.s2ip
  end
  local parse_udp
  parse_udp = require("ipparse.l4.udp").parse
  local build_response
  build_response = function(rcode)
    local question = qname_example .. sp(">H H", QTYPE_A, QCLASS_IN)
    local dns = sp(">H H H H H H", 0x1234, 0x8000 + rcode, 1, 0, 0, 0) .. question
    local udp_len = 8 + #dns
    local total = 20 + udp_len
    local raw = sp(">B B H H H B B H", 0x45, 0, total, 0x1, 0, 64, 17, 0)
    raw = raw .. (s2ip("1.1.1.1") .. s2ip("10.35.8.2"))
    raw = raw .. (sp(">H H H H", 53, 5353, udp_len, 0) .. dns)
    local ip, _ = parse_ip(raw)
    local l4
    l4, _ = parse_udp(raw, ip.data_off)
    l4.proto = "udp"
    return ip, l4, dns
  end
  local load_with_retry
  load_with_retry = function(cfg)
    local config = require("config")
    config.dns = {
      ttl_grace = {
        grace = 0,
        min = 60,
        max = 900
      },
      upstream_retry = cfg
    }
    config.ipc = {
      pending_ttl = 5
    }
    local sent = { }
    package.loaded["raw_send"] = {
      open = function(ver)
        return 40 + ver
      end,
      routable = function()
        return true
      end,
      send = function(fd, ver, pkt, dst)
        sent[#sent + 1] = {
          fd = fd,
          ver = ver,
          pkt = pkt,
          dst = dst
        }
      end
    }
    local m = fresh_worker_responses()
    m.arm_retry_fds()
    return m, sent
  end
  local mk_msg
  mk_msg = function(rcode)
    return {
      header = {
        ra_z_rcode = rcode,
        qdcount = 1
      },
      questions = {
        {
          name = "example.com"
        }
      }
    }
  end
  it("réémet et renvoie true sur SERVFAIL dans le budget", function()
    local m, sent = load_with_retry({
      enabled = true,
      max_attempts = 2,
      rcodes = {
        2,
        5
      }
    })
    local ip, l4, dns = build_response(2)
    local entry = {
      refused = false
    }
    assert.is_true((m.try_upstream_retry(entry, mk_msg(2), dns, ip, l4, "1.1.1.1")))
    assert.equals(1, entry.upstream_retries)
    assert.equals(1, #sent)
    return assert.equals("1.1.1.1", sent[1].dst)
  end)
  it("n'émet plus au-delà de max_attempts", function()
    local m, sent = load_with_retry({
      enabled = true,
      max_attempts = 2,
      rcodes = {
        2
      }
    })
    local ip, l4, dns = build_response(2)
    assert.is_false((m.try_upstream_retry({
      refused = false,
      upstream_retries = 2
    }, mk_msg(2), dns, ip, l4, "1.1.1.1")))
    return assert.equals(0, #sent)
  end)
  it("ignore un rcode non listé (NXDOMAIN)", function()
    local m, sent = load_with_retry({
      enabled = true,
      max_attempts = 2,
      rcodes = {
        2,
        5
      }
    })
    local ip, l4, dns = build_response(3)
    assert.is_false((m.try_upstream_retry({
      refused = false
    }, mk_msg(3), dns, ip, l4, "1.1.1.1")))
    return assert.equals(0, #sent)
  end)
  it("ne retry pas une transaction refused", function()
    local m, sent = load_with_retry({
      enabled = true,
      max_attempts = 2,
      rcodes = {
        2
      }
    })
    local ip, l4, dns = build_response(2)
    return assert.is_false((m.try_upstream_retry({
      refused = true
    }, mk_msg(2), dns, ip, l4, "1.1.1.1")))
  end)
  it("désactivé par config → false", function()
    local m, sent = load_with_retry({
      enabled = false
    })
    local ip, l4, dns = build_response(2)
    return assert.is_false((m.try_upstream_retry({
      refused = false
    }, mk_msg(2), dns, ip, l4, "1.1.1.1")))
  end)
  it("retente un NXDOMAIN tant que le budget le permet", function()
    local m, sent = load_with_retry({
      enabled = true,
      max_attempts = 2,
      rcodes = {
        2,
        3,
        5
      }
    })
    local ip, l4, dns = build_response(3)
    local entry = {
      refused = false
    }
    assert.is_true((m.try_upstream_retry(entry, mk_msg(3), dns, ip, l4, "1.1.1.1")))
    assert.equals(1, entry.upstream_retries)
    return assert.equals(1, #sent)
  end)
  it("mémorise un nom durablement NXDOMAIN et n'y retente plus", function()
    local m, sent = load_with_retry({
      enabled = true,
      max_attempts = 1,
      rcodes = {
        3
      }
    })
    local ip, l4, dns = build_response(3)
    assert.is_false((m.try_upstream_retry({
      refused = false,
      upstream_retries = 1
    }, mk_msg(3), dns, ip, l4, "1.1.1.1")))
    assert.is_false((m.try_upstream_retry({
      refused = false
    }, mk_msg(3), dns, ip, l4, "1.1.1.1")))
    return assert.equals(0, #sent)
  end)
  return it("une réponse NOERROR réhabilite un nom et autorise de nouveau le retry", function()
    local m, sent = load_with_retry({
      enabled = true,
      max_attempts = 1,
      rcodes = {
        3
      }
    })
    local ip3, l43, dns3 = build_response(3)
    local ip0, l40, dns0 = build_response(0)
    assert.is_false((m.try_upstream_retry({
      refused = false,
      upstream_retries = 1
    }, mk_msg(3), dns3, ip3, l43, "1.1.1.1")))
    assert.is_false((m.try_upstream_retry({
      refused = false
    }, mk_msg(3), dns3, ip3, l43, "1.1.1.1")))
    assert.is_false((m.try_upstream_retry({
      refused = false
    }, mk_msg(0), dns0, ip0, l40, "1.1.1.1")))
    local entry = {
      refused = false
    }
    assert.is_true((m.try_upstream_retry(entry, mk_msg(3), dns3, ip3, l43, "1.1.1.1")))
    return assert.equals(1, entry.upstream_retries)
  end)
end)
