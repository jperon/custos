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
      ipc_retry_wait_ms = 3,
      ipc_retry_attempts = 1
    }
    local deltas = {
      delta_ms = 12,
      question_proc_ms = 4,
      response_entry_ms = 5,
      drain_ms = 0,
      payload_ms = 1,
      parse_ms = 2,
      match_ms = 0,
      log_ms = 0,
      ack_wait_us = 1234,
      log_write_us = 42
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
      assert.equals(1234, fields.ack_wait_us)
      assert.equals(42, fields.log_write_us)
      assert.equals("0x1f4d", fields.txid)
      assert.equals(1, fields.ipc_retry_attempts)
      assert.equals(3, fields.ipc_retry_wait_ms)
      assert.is_nil(fields.retry_attempts)
      return assert.is_nil(fields.retry_wait_ms)
    end)
    it("ack_wait_us et log_write_us valent 0 quand aucune mesure n'est fournie", function()
      local m = fresh_worker_responses()
      local entry = {
        refused = false,
        reason = "Allowed",
        rule_id = "r_ok",
        dnsonly = false
      }
      local no_us = {
        delta_ms = 5,
        question_proc_ms = 1,
        response_entry_ms = 2,
        drain_ms = 0,
        payload_ms = 1,
        parse_ms = 1,
        match_ms = 0,
        log_ms = 0
      }
      local fields = m.build_benchmark_fields(entry, info, no_us)
      assert.equals(0, fields.ack_wait_us)
      assert.equals(0, fields.log_write_us)
      return assert.equals(5, fields.q_to_response_ms)
    end)
    it("upstream_retries reflète entry.upstream_retries (compteur upstream)", function()
      local m = fresh_worker_responses()
      local entry = {
        refused = false,
        reason = "Allowed",
        rule_id = "r_ok",
        dnsonly = false,
        upstream_retries = 2
      }
      local fields = m.build_benchmark_fields(entry, info, deltas)
      assert.equals(2, fields.upstream_retries)
      assert.equals(1, fields.ipc_retry_attempts)
      return assert.equals(3, fields.ipc_retry_wait_ms)
    end)
    it("upstream_retries vaut 0 quand la transaction n'a pas été retentée", function()
      local m = fresh_worker_responses()
      local no_retry_info = {
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
        ipc_retry_attempts = 0,
        ipc_retry_wait_ms = 0
      }
      local entry = {
        refused = false,
        reason = "Allowed",
        rule_id = "r_ok",
        dnsonly = false
      }
      local fields = m.build_benchmark_fields(entry, no_retry_info, deltas)
      assert.equals(0, fields.upstream_retries)
      assert.equals(0, fields.ipc_retry_attempts)
      return assert.equals(0, fields.ipc_retry_wait_ms)
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
describe("worker_responses upstream retry", function()
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
    local ip, _ = parse_ip(raw, 1)
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
describe("mac_clients / ip_to_mac (update_mac_clients, purge_mac_clients)", function()
  it("la purge d'une ancienne MAC ne supprime pas le mapping du nouveau propriétaire", function()
    local m = fresh_worker_responses()
    m.update_mac_clients({
      mac_str = "aa:aa:aa:aa:aa:aa",
      ipv4 = true,
      ip_str = "10.0.0.1"
    }, 1)
    assert.equals("aa:aa:aa:aa:aa:aa", m.ip_to_mac["10.0.0.1"])
    m.update_mac_clients({
      mac_str = "bb:bb:bb:bb:bb:bb",
      ipv4 = true,
      ip_str = "10.0.0.1"
    }, 2)
    assert.equals("bb:bb:bb:bb:bb:bb", m.ip_to_mac["10.0.0.1"])
    m.purge_mac_clients(302)
    return assert.equals("bb:bb:bb:bb:bb:bb", m.ip_to_mac["10.0.0.1"])
  end)
  it("une MAC seule qui expire voit bien son IP retirée (contrôle)", function()
    local m = fresh_worker_responses()
    m.update_mac_clients({
      mac_str = "cc:cc:cc:cc:cc:cc",
      ipv4 = true,
      ip_str = "10.0.0.9"
    }, 1)
    assert.equals("cc:cc:cc:cc:cc:cc", m.ip_to_mac["10.0.0.9"])
    m.purge_mac_clients(302)
    return assert.is_nil(m.ip_to_mac["10.0.0.9"])
  end)
  return it("changement d'IP d'une MAC ne supprime pas le mapping d'un autre propriétaire", function()
    local m = fresh_worker_responses()
    m.update_mac_clients({
      mac_str = "aa:aa:aa:aa:aa:aa",
      ipv4 = true,
      ip_str = "10.0.0.1"
    }, 1)
    m.update_mac_clients({
      mac_str = "bb:bb:bb:bb:bb:bb",
      ipv4 = true,
      ip_str = "10.0.0.1"
    }, 2)
    m.update_mac_clients({
      mac_str = "aa:aa:aa:aa:aa:aa",
      ipv4 = true,
      ip_str = "10.0.0.2"
    }, 3)
    assert.equals("bb:bb:bb:bb:bb:bb", m.ip_to_mac["10.0.0.1"])
    return assert.equals("aa:aa:aa:aa:aa:aa", m.ip_to_mac["10.0.0.2"])
  end)
end)
local ffi = require("ffi")
pcall(ffi.cdef, [[  int pipe2(int pipefd[2], int flags);
  int close(int fd);
  ssize_t read(int fd, void *buf, size_t count);
  int* __errno_location();
]])
describe("budget de retry d'appariement IPC", function()
  local saved_match_retry = nil
  before_each(function()
    local config = require("config")
    config.ipc = config.ipc or { }
    saved_match_retry = config.ipc.match_retry
  end)
  after_each(function()
    local config = require("config")
    config.ipc.match_retry = saved_match_retry
    package.loaded["ipc"] = nil
    package.loaded["worker_responses"] = nil
  end)
  local load_with_match_retry
  load_with_match_retry = function(retry_cfg)
    local config = require("config")
    config.ipc = config.ipc or { }
    config.ipc.pending_ttl = 5
    config.ipc.match_retry = retry_cfg
    package.loaded["ipc"] = nil
    package.loaded["worker_responses"] = nil
    return dofile("lua/worker_responses.lua")
  end
  local make_pipe
  make_pipe = function()
    local pipefd = ffi.new("int[2]")
    assert.equals(0, ffi.C.pipe2(pipefd, 2048))
    return {
      pipefd[0],
      pipefd[1]
    }
  end
  describe("plan_retry_tries (fonction pure)", function()
    it("autorise toutes les tentatives quand le budget est intact", function()
      local m = fresh_worker_responses()
      return assert.equals(5, m.plan_retry_tries(0, 100, 20, 5))
    end)
    it("borne les tentatives au budget restant", function()
      local m = fresh_worker_responses()
      assert.equals(1, m.plan_retry_tries(80, 100, 20, 5))
      return assert.equals(4, m.plan_retry_tries(20, 100, 20, 5))
    end)
    it("retourne 0 quand le budget restant est insuffisant", function()
      local m = fresh_worker_responses()
      assert.equals(0, m.plan_retry_tries(85, 100, 20, 5))
      assert.equals(0, m.plan_retry_tries(100, 100, 20, 5))
      return assert.equals(0, m.plan_retry_tries(0, 0, 20, 5))
    end)
    it("ne borne pas les tentatives gratuites (sleep_ms = 0)", function()
      local m = fresh_worker_responses()
      return assert.equals(5, m.plan_retry_tries(1000, 100, 0, 5))
    end)
    return it("ne dépasse jamais le nombre de tentatives configuré", function()
      local m = fresh_worker_responses()
      return assert.equals(2, m.plan_retry_tries(0, 100000, 20, 2))
    end)
  end)
  return describe("retry_pending_match borné", function()
    it("une rafale ne consomme qu'un budget par seconde puis saute le retry", function()
      local m = load_with_match_retry({
        enabled = true,
        count = 5,
        sleep_ms = 20,
        budget_ms = 100
      })
      local p = make_pipe()
      m._set_pipe_rfd(p[1])
      local entry1, attempts1, wait1, skipped1 = m.retry_pending_match(0x1234, "10.0.0.2", 5353, "1.1.1.1", 1000)
      assert.is_nil(entry1)
      assert.equals(5, attempts1, "budget intact : les 5 tentatives configurées ont lieu")
      assert.equals(100, wait1)
      assert.is_false(skipped1)
      local entry2, attempts2, wait2, skipped2 = m.retry_pending_match(0x1234, "10.0.0.2", 5353, "1.1.1.1", 1000)
      assert.is_nil(entry2)
      assert.equals(0, attempts2, "retry sauté : aucun nanosleep")
      assert.equals(0, wait2, "aucun sommeil consommé")
      assert.is_true(skipped2, "budget_skipped signale la borne atteinte")
      local _, attempts3, skipped3
      _, attempts3, _, skipped3 = m.retry_pending_match(0x1234, "10.0.0.2", 5353, "1.1.1.1", 1001)
      assert.equals(5, attempts3)
      assert.is_false(skipped3)
      ffi.C.close(p[1])
      return ffi.C.close(p[2])
    end)
    return it("préserve le retry du cas nominal (réordonnancement IPC absorbé)", function()
      local m = load_with_match_retry({
        enabled = true,
        count = 5,
        sleep_ms = 20,
        budget_ms = 100
      })
      local ipc = require("ipc")
      local p = make_pipe()
      m._set_pipe_rfd(p[1])
      ipc.write_msg(p[2], 0x1234, "\x0a\x00\x00\x02", 5353, "\xaa\xbb\xcc\xdd\xee\xff", "\x01\x01\x01\x01", "ok", nil, "r_ok")
      local entry, attempts, wait, skipped = m.retry_pending_match(0x1234, "10.0.0.2", 5353, "1.1.1.1", 1000)
      assert.is_not_nil(entry, "la question est appariée après le premier drain")
      assert.equals(1, attempts)
      assert.equals(20, wait)
      assert.is_false(skipped)
      assert.equals("r_ok", entry.rule_id)
      assert.equals(20, m._retry_budget.used_ms)
      ffi.C.close(p[1])
      return ffi.C.close(p[2])
    end)
  end)
end)
describe("build_orphan_fields (trace INFO du drop orphelin)", function()
  local base_info = {
    src_ip = "1.1.1.1",
    dst_ip = "10.0.0.2",
    dst_port = 5353,
    vlan = 8,
    txid = "0x1234",
    qname = "example.com",
    rcode = 0,
    client_mac = "aa:bb:cc:dd:ee:ff",
    user = "alice@lan",
    ipc_retry_attempts = 0,
    ipc_retry_wait_ms = 0,
    retry_budget_skipped = false
  }
  it("produit une action dédiée avec les champs d'enquête", function()
    local m = fresh_worker_responses()
    local f = m.build_orphan_fields(base_info)
    assert.equals("response_orphan_dropped", f.action)
    assert.equals("0x1234", f.txid)
    assert.equals("10.0.0.2", f.dst_ip)
    assert.equals(5353, f.dst_port)
    assert.equals("1.1.1.1", f.src_ip)
    assert.equals("example.com", f.qname)
    assert.equals("aa:bb:cc:dd:ee:ff", f.client_mac)
    assert.equals(8, f.vlan)
    assert.equals(0, f.rcode)
    return assert.equals(0, f.retry_budget_skipped)
  end)
  it("traduit le budget épuisé et les compteurs de retry", function()
    local m = fresh_worker_responses()
    local info = { }
    for k, v in pairs(base_info) do
      info[k] = v
    end
    info.retry_budget_skipped = true
    info.ipc_retry_attempts = 2
    info.ipc_retry_wait_ms = 40
    local f = m.build_orphan_fields(info)
    assert.equals(1, f.retry_budget_skipped, "budget épuisé signalé dans la trace")
    assert.equals(2, f.ipc_retry_attempts)
    return assert.equals(40, f.ipc_retry_wait_ms)
  end)
  return it("qname absent → '-' (jamais nil dans la ligne)", function()
    local m = fresh_worker_responses()
    local info = { }
    for k, v in pairs(base_info) do
      info[k] = v
    end
    info.qname = nil
    return assert.equals("-", (m.build_orphan_fields(info)).qname)
  end)
end)
describe("verdicts différés par lot NFQUEUE (settle / flush_deferred)", function()
  local calls = nil
  local m = nil
  before_each(function()
    m = fresh_worker_responses()
    calls = {
      set = { },
      waits = { },
      seq_reads = 0,
      seq = nil
    }
    return m._set_defer_deps({
      get_last_seq = function()
        calls.seq_reads = calls.seq_reads + 1
        return calls.seq
      end,
      wait_ack = function(seq, corr, on_wait)
        calls.waits[#calls.waits + 1] = {
          seq = seq,
          corr = corr
        }
        return true
      end,
      set_verdict = function(qh, id, verdict, payload)
        calls.set[#calls.set + 1] = {
          qh = qh,
          id = id,
          verdict = verdict,
          payload = payload
        }
      end
    })
  end)
  it("en mode lot, settle mémorise le verdict sans attente ni verdict posé", function()
    local ctx = {
      qh_ptr = "qh",
      pkt_id = 11,
      ack_corr = "c1",
      defer = true
    }
    m.settle(ctx, 1, nil, true)
    m.settle(ctx, 1, "payload", true)
    assert.equals(2, m.deferred_count())
    assert.equals(0, #calls.set)
    assert.equals(0, #calls.waits)
    return assert.equals(0, calls.seq_reads)
  end)
  it("flush_deferred pose tous les verdicts après UN SEUL ACK du plus grand seq", function()
    local ctx1 = {
      qh_ptr = "qh",
      pkt_id = 11,
      ack_corr = "c1",
      defer = true
    }
    local ctx2 = {
      qh_ptr = "qh",
      pkt_id = 12,
      ack_corr = "c2",
      defer = true
    }
    m.settle(ctx1, 1, nil, true)
    m.settle(ctx2, 1, "patched", true)
    calls.seq = 42
    local n = m.flush_deferred()
    assert.equals(2, n)
    assert.equals(1, #calls.waits)
    assert.equals(42, calls.waits[1].seq)
    assert.equals("c2", calls.waits[1].corr)
    assert.equals(2, #calls.set)
    assert.equals(11, calls.set[1].id)
    assert.is_nil(calls.set[1].payload)
    assert.equals(12, calls.set[2].id)
    assert.equals("patched", calls.set[2].payload)
    return assert.equals(0, m.deferred_count())
  end)
  it("flush_deferred sans insertion enfilée (seq nil) ne fait aucune attente", function()
    local ctx = {
      qh_ptr = "qh",
      pkt_id = 7,
      ack_corr = "c",
      defer = true
    }
    m.settle(ctx, 1, nil, false)
    local n = m.flush_deferred()
    assert.equals(1, n)
    assert.equals(0, #calls.waits)
    return assert.equals(1, #calls.set)
  end)
  it("flush_deferred vide ne fait rien", function()
    assert.equals(0, m.flush_deferred())
    assert.equals(0, calls.seq_reads)
    return assert.equals(0, #calls.set)
  end)
  it("hors lot, settle attend une fois puis pose le verdict", function()
    local ctx = {
      qh_ptr = "qh",
      pkt_id = 3,
      ack_corr = "corr"
    }
    calls.seq = 9
    m.settle(ctx, 1, nil, true)
    assert.equals(1, #calls.waits)
    assert.equals(9, calls.waits[1].seq)
    assert.equals("corr", calls.waits[1].corr)
    assert.equals(1, #calls.set)
    return assert.equals(3, calls.set[1].id)
  end)
  it("hors lot, settle sans insertion à acquitter ne fait aucune attente", function()
    local ctx = {
      qh_ptr = "qh",
      pkt_id = 4,
      ack_corr = "corr"
    }
    calls.seq = 9
    m.settle(ctx, 1, "patched", false)
    assert.equals(0, #calls.waits)
    assert.equals(1, #calls.set)
    return assert.equals("patched", calls.set[1].payload)
  end)
  it("une erreur du chemin de verdict est journalisée, pas propagée", function()
    local ctx = {
      qh_ptr = "qh",
      pkt_id = 8,
      ack_corr = "c",
      defer = true
    }
    m.settle(ctx, 1, nil, true)
    m._set_defer_deps({
      get_last_seq = function()
        return 1
      end,
      wait_ack = function()
        return true
      end,
      set_verdict = function()
        return error("boom")
      end
    })
    local n = m.flush_deferred()
    assert.equals(1, n)
    return assert.equals(0, m.deferred_count())
  end)
  return it("hors lot, dnsonly avec insertion captive_probe attend l'ACK", function()
    local ctx = {
      qh_ptr = "qh",
      pkt_id = 5,
      ack_corr = "corr",
      dnsonly = true
    }
    calls.seq = 9
    m.settle(ctx, 1, nil, true)
    assert.equals(1, #calls.waits)
    return assert.equals(1, #calls.set)
  end)
end)
describe("worker_responses helpers complémentaires (couverture)", function()
  before_each(function()
    local config = require("config")
    config.ipc = config.ipc or { }
    config.ipc.match_retry = {
      enabled = true,
      count = 5,
      sleep_ms = 0,
      budget_ms = 100
    }
  end)
  it("format_block_event sans timestamp utilise os.time", function()
    local m = fresh_worker_responses()
    local line = m.format_block_event({
      qname = "exemple.test"
    })
    assert.truthy(line:match("^%d+\tblock\t"))
    assert.truthy(line:match("exemple.test"))
    return assert.equals("exemple.test", (line:gsub("\n", "")):match("\tblock\t([^\t]+)"))
  end)
  it("update_mac_clients : changement d'IPv6 oublie l'ancien mapping de cette MAC", function()
    local m = fresh_worker_responses()
    m.update_mac_clients({
      mac_str = "aa:aa:aa:aa:aa:aa",
      ip_str = "2001:db8::1"
    }, 1)
    assert.equals("aa:aa:aa:aa:aa:aa", m.ip_to_mac["2001:db8::1"])
    m.update_mac_clients({
      mac_str = "aa:aa:aa:aa:aa:aa",
      ip_str = "2001:db8::2"
    }, 2)
    assert.is_nil(m.ip_to_mac["2001:db8::1"])
    return assert.equals("aa:aa:aa:aa:aa:aa", m.ip_to_mac["2001:db8::2"])
  end)
  it("update_mac_clients ignore la MAC nulle (inconnue)", function()
    local m = fresh_worker_responses()
    m.update_mac_clients({
      mac_str = "00:00:00:00:00:00",
      ipv4 = true,
      ip_str = "10.0.0.1"
    }, 1)
    return assert.is_nil(m.ip_to_mac["10.0.0.1"])
  end)
  it("maybe_dynamic_strip sans entrée ou sans rr_code renvoie la réponse intacte", function()
    local m = fresh_worker_responses()
    local raw = "payload"
    assert.same({
      raw,
      false
    }, {
      m.maybe_dynamic_strip("a.test", raw, function()
        return nil
      end)
    })
    return assert.same({
      raw,
      false
    }, {
      m.maybe_dynamic_strip(nil, raw, function()
        return 3
      end)
    })
  end)
  it("_reset_deferred vide la file de verdicts différés", function()
    local m = fresh_worker_responses()
    m.settle({
      qh_ptr = "qh",
      pkt_id = 1,
      defer = true
    }, 1, nil, false)
    assert.equals(1, m.deferred_count())
    m._reset_deferred()
    assert.equals(0, m.deferred_count())
    return assert.equals(0, m.flush_deferred())
  end)
  it("retry_pending_match est inactif si le retry est désactivé", function()
    local config = require("config")
    config.ipc.match_retry = {
      enabled = false,
      count = 5,
      sleep_ms = 0
    }
    local m = fresh_worker_responses()
    local entry, tries, waited, budget = m.retry_pending_match("tx", "10.0.0.1", 1, "1.1.1.1", 10)
    assert.is_nil(entry)
    assert.equals(0, tries)
    assert.equals(0, waited)
    return assert.is_false(budget)
  end)
  return it("retry_pending_match est inactif si count vaut 0", function()
    local config = require("config")
    config.ipc.match_retry = {
      enabled = true,
      count = 0,
      sleep_ms = 0
    }
    local m = fresh_worker_responses()
    local entry, tries, waited, budget = m.retry_pending_match("tx", "10.0.0.1", 1, "1.1.1.1", 10)
    assert.is_nil(entry)
    assert.equals(0, tries)
    assert.equals(0, waited)
    return assert.is_false(budget)
  end)
end)
return describe("worker_responses : drain du tube sans paquet NFQUEUE", function()
  local saved_nfq = nil
  local captured = nil
  local p = nil
  local m_ipc = nil
  local m = nil
  local purges = 0
  before_each(function()
    local cfg = require("config")
    cfg.ipc = cfg.ipc or { }
    cfg.ipc.pending_ttl = 5
    cfg.ipc.match_retry = {
      enabled = false
    }
    saved_nfq = package.loaded["nfq_loop"]
    captured = nil
    purges = 0
    package.loaded["nfq_loop"] = {
      run_queue = function(queue, cb, opts)
        captured = {
          queue = queue,
          cb = cb,
          opts = opts
        }
        return nil
      end,
      NF_ACCEPT = 1,
      NF_DROP = 0
    }
    package.loaded["ipc"] = nil
    m_ipc = require("ipc")
    local proxy = setmetatable({
      purge_pending = function(now_fn)
        purges = purges + 1
        return m_ipc.purge_pending(now_fn)
      end
    }, {
      __index = m_ipc
    })
    package.loaded["ipc"] = proxy
    package.loaded["worker_responses"] = nil
    m = dofile("lua/worker_responses.lua")
    local pipefd = ffi.new("int[2]")
    assert.equals(0, ffi.C.pipe2(pipefd, 2048))
    p = {
      pipefd[0],
      pipefd[1]
    }
  end)
  after_each(function()
    package.loaded["nfq_loop"] = saved_nfq
    package.loaded["ipc"] = nil
    package.loaded["worker_responses"] = nil
    if p then
      ffi.C.close(p[1])
      return ffi.C.close(p[2])
    end
  end)
  it("surveille le tube et absorbe les questions sans paquet", function()
    m.run(15, p[1], nil)
    assert.is_not_nil(captured, "run_queue doit être appelé")
    assert.equals(15, captured.queue)
    assert.is_not_nil(captured.opts.extra_rfds)
    assert.equals(1, #captured.opts.extra_rfds, "le tube question→réponse est surveillé")
    assert.equals(p[1], captured.opts.extra_rfds[1])
    assert.is_function(captured.opts.on_extra_ready)
    for i = 1, 5 do
      assert.is_true(m_ipc.write_msg(p[2], 0x7000 + i, "\x0a\x00\x00\x02", 5353, "\xaa\xbb\xcc\xdd\xee\xff", "\x01\x01\x01\x01", "ok", nil, "r_ok"))
    end
    assert.is_false((m_ipc.is_pending(0x7001, "10.0.0.2", 5353, "1.1.1.1", function()
      return os.time()
    end)))
    captured.opts.on_extra_ready()
    for i = 1, 5 do
      assert.is_true((m_ipc.is_pending(0x7000 + i, "10.0.0.2", 5353, "1.1.1.1", function()
        return os.time()
      end)), "question " .. tostring(i) .. " absorbée sans paquet")
    end
  end)
  it("purge l'expiration pending au plus une fois tous les 64 réveils", function()
    m.run(15, p[1], nil)
    assert.is_true(m_ipc.write_msg(p[2], 0x7100, "\x0a\x00\x00\x02", 5353, "\xaa\xbb\xcc\xdd\xee\xff", "\x01\x01\x01\x01", "ok", nil, "r_ok"))
    captured.opts.on_extra_ready()
    assert.equals(0, purges, "pas de purge à chaque réveil (coût O(pending))")
    for i = 1, 63 do
      captured.opts.on_extra_ready()
    end
    return assert.equals(1, purges)
  end)
  return it("un tube PLEIN est drainé par un seul réveil (capacité rendue)", function()
    m.run(15, p[1], nil)
    local written = 0
    for i = 1, 2000 do
      local ok = m_ipc.write_msg(p[2], 0x7200 + (i % 256), "\x0a\x00\x00\x02", 5353, "\xaa\xbb\xcc\xdd\xee\xff", "\x01\x01\x01\x01", "ok", nil, "r_fill")
      if not (ok) then
        break
      end
      written = written + 1
    end
    assert.is_true(written > 100, "tube rempli (" .. tostring(written) .. " messages)")
    assert.is_false(m_ipc.write_msg(p[2], 0x7300, "\x0a\x00\x00\x02", 5353, "\xaa\xbb\xcc\xdd\xee\xff", "\x01\x01\x01\x01", "ok", nil, "r_fill"))
    captured.opts.on_extra_ready()
    return assert.is_true(m_ipc.write_msg(p[2], 0x7301, "\x0a\x00\x00\x02", 5353, "\xaa\xbb\xcc\xdd\xee\xff", "\x01\x01\x01\x01", "ok", nil, "r_fill"))
  end)
end)
