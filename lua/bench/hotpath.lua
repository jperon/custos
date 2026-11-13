local ffi = require("ffi")
local gc_tune = require("lib.gc_tune")
local stage_probe = require("bench.stage_probe")
local s2ip
s2ip = require("ipparse.l3.ip").s2ip
local sp = require("ipparse.lib.pack_compat").pack
local libc = ffi.C
local PROF_DIR = "tmp/prof"
local SESSIONS_PATH = PROF_DIR .. "/sessions.lua"
local OUT_PATH = PROF_DIR .. "/hotpath.md"
local CLIENT_IP = "10.35.1.2"
local CLIENT_PORT = 5353
local RESOLVER_IP = "10.35.1.1"
local VALIDATOR_IP = "10.35.4.1"
local CLIENT_MAC = "d8:d3:85:63:6b:27"
local CLIENT_USER = "j@prn.ovh"
local CLIENT_MAC_RAW = string.char(0xd8, 0xd3, 0x85, 0x63, 0x6b, 0x27)
local QNAME_TLS = "controlplane.login.tailscale.com"
local QNAME_VPN = "vpn.stemarie.dynv6.net"
local TXID = 0x1234
local ADDRS_TLS = {
  "100.64.0.11",
  "100.64.0.12",
  "100.64.0.13",
  "100.64.0.14",
  "100.64.0.15",
  "100.64.0.16",
  "100.64.0.17",
  "100.64.0.18"
}
local ADDRS_VPN = {
  "185.199.108.153"
}
local ADDRS_B = {
  "167.235.236.107"
}
local ADDRS_VAL = ADDRS_TLS
local O_NONBLOCK = 2048
local F_SETPIPE_SZ = 1031
local NFT_PIPE_BYTES = 1048576
local NF_ACCEPT = 1
local NF_DROP = 0
local payload_buf = ffi.new("uint8_t[65536]")
local payload_ptr = ffi.cast("unsigned char*", payload_buf)
local payload_len = 0
local hw_hdr = nil
local hw_ptr = nil
local verdicts = 0
local dup_sent = 0
local run_queue_calls = { }
local BENCH_RULES = {
  {
    rule_id = "r_utilisateurs",
    description = "Utilisateurs",
    actions = {
      "allow",
      {
        validate = { }
      }
    },
    conditions = {
      to_domains = {
        QNAME_TLS,
        "login.tailscale.com",
        "dns.tailscale.com",
        "tailscale.com"
      }
    }
  },
  {
    rule_id = "r_ouverture_complete",
    description = "Ouverture complète",
    actions = {
      "allow"
    },
    conditions = {
      to_domains = {
        QNAME_VPN,
        "dynv6.net"
      }
    }
  },
  {
    rule_id = "r_refus_a_priori",
    description = "Refus a priori",
    actions = {
      "deny"
    }
  }
}
local ALL_CASES = {
  "question",
  "ipc_drain",
  "response",
  "so_a",
  "so_cycle",
  "mixed_o2",
  "mixed_plain",
  "setup_control"
}
local encode_name
encode_name = function(name)
  local parts = { }
  for label in (name:gmatch("[^%.]+")) do
    parts[#parts + 1] = string.char(#label) .. label
  end
  return table.concat(parts) .. "\0"
end
local build_query
build_query = function(qname, txid)
  if txid == nil then
    txid = TXID
  end
  local header = sp(">H H H H H H", txid, 0x0100, 1, 0, 0, 0)
  return header .. encode_name(qname) .. sp(">H H", 1, 1)
end
local build_answer
build_answer = function(qname, txid, addrs, opts)
  if opts == nil then
    opts = nil
  end
  opts = opts or { }
  local ttl = opts.ttl or 60
  local flags = opts.flags or 0x8180
  local header = sp(">H H H H H H", txid, flags, 1, #addrs, 0, 0)
  local qsection = encode_name(qname) .. sp(">H H", 1, 1)
  local parts = { }
  for _index_0 = 1, #addrs do
    local ip = addrs[_index_0]
    parts[#parts + 1] = "\192\012" .. sp(">H H I4 H", 1, 1, ttl, 4) .. s2ip(ip)
  end
  return header .. qsection .. table.concat(parts)
end
local ipv4_udp
ipv4_udp = function(src, dst, sport, dport, dns)
  local udp_len = 8 + #dns
  local total = 20 + udp_len
  local hdr = sp(">B B H H H B B H", 0x45, 0, total, 0x2222, 0, 64, 17, 0)
  return hdr .. s2ip(src) .. s2ip(dst) .. sp(">H H H H", sport, dport, udp_len, 0) .. dns
end
local build_question_packet
build_question_packet = function(qname)
  return ipv4_udp(CLIENT_IP, RESOLVER_IP, CLIENT_PORT, 53, build_query(qname))
end
local build_response_packet
build_response_packet = function(src, qname, addrs, opts)
  if opts == nil then
    opts = nil
  end
  return ipv4_udp(src, CLIENT_IP, 53, CLIENT_PORT, build_answer(qname, TXID, addrs, opts))
end
local top_n
top_n = function(counts, n)
  local list = { }
  for k, v in pairs(counts) do
    list[#list + 1] = {
      key = k,
      count = v
    }
  end
  table.sort(list, function(a, b)
    return a.count > b.count
  end)
  local out = { }
  for i = 1, math.min(n, #list) do
    out[#out + 1] = list[i]
  end
  return out
end
local format_pct
format_pct = function(part, total)
  if total > 0 then
    return string.format("%.1f", 100 * part / total)
  else
    return "0.0"
  end
end
local write_file
write_file = function(path, lines)
  local fh = io.open(path, "w")
  if not (fh) then
    return false
  end
  fh:write(table.concat(lines, "\n"))
  fh:write("\n")
  fh:close()
  return true
end
local install_stubs
install_stubs = function()
  local real = require("ffi_defs")
  hw_hdr = ffi.new("nfqnl_msg_packet_hw[1]")
  ffi.copy(hw_hdr[0].hw_addr, CLIENT_MAC_RAW, 6)
  hw_hdr[0].hw_addrlen = 6
  hw_ptr = ffi.cast("nfqnl_msg_packet_hw*", hw_hdr)
  local overrides = {
    nfq_get_payload = function(nfad, out)
      out[0] = payload_ptr
      return payload_len
    end,
    nfq_set_verdict = function(qh, id, verdict, datalen, buf)
      verdicts = verdicts + 1
      return 0
    end,
    nfq_set_verdict2 = function(qh, id, verdict, mark, datalen, buf)
      verdicts = verdicts + 1
      return 0
    end,
    nfq_get_packet_hw = function(nfad)
      return hw_ptr
    end,
    nfq_get_indev = function(nfad)
      return 5
    end,
    nfq_get_nfmark = function(nfad)
      return 0
    end
  }
  package.loaded["ffi_defs"] = {
    ffi = real.ffi,
    libc = real.libc,
    libnfq = setmetatable(overrides, {
      __index = real.libnfq
    }),
    libnft = real.libnft,
    libwolfssl = real.libwolfssl
  }
  package.loaded["raw_send"] = {
    open = function(version)
      return 42
    end,
    routable = function(version, dst)
      return true
    end,
    send = function(fd, version, pkt, dst)
      dup_sent = dup_sent + 1
      return true
    end,
    IPPROTO_RAW = 255,
    IPPROTO_UDP = 17
  }
  local nfq_loop = require("nfq_loop")
  nfq_loop.run_queue = function(queue_num, callback, opts)
    run_queue_calls[#run_queue_calls + 1] = {
      queue_num = queue_num,
      callback = callback,
      opts = opts
    }
    return nil
  end
  return nil
end
local install_probes
install_probes = function(p)
  p.wrap(require("packet_utils"), "parse_dns_packet", "parse_dns_packet")
  p.wrap(require("ipc"), "drain_pipe", "ipc.drain_pipe")
  p.wrap(require("ipc"), "get_pending_entry", "ipc.get_pending_entry")
  p.wrap(require("ipc"), "consume", "ipc.consume")
  p.wrap(require("ipc"), "write_msg", "ipc.write_msg")
  p.wrap(require("lib.dns_response"), "parse_answers", "parse_answers")
  p.wrap(require("lib.dns_response"), "replace_dns_payload", "replace_dns_payload")
  p.wrap(require("dns_ede"), "patch_modified_dns", "patch_modified_dns")
  p.wrap(require("dns_ede"), "strip_https_rr", "strip_https_rr")
  p.wrap(require("dns_classify"), "classify", "dns_classify.classify")
  p.wrap(require("second_opinion"), "encode_verdict", "encode_verdict")
  p.wrap_state(require("second_opinion"), "new", {
    "corr_key",
    "take_verdict",
    "store_verdict",
    "take_parked",
    "park",
    "is_validator"
  })
  p.wrap(require("response_inject"), "inject", "response_inject.inject")
  p.wrap(require("nft_queue"), "add_ip4", "nft.add_ip4")
  p.wrap(require("nft_queue"), "add_mac4", "nft.add_mac4")
  p.wrap(require("auth.sessions"), "user_for_mac", "user_for_mac")
  p.wrap(require("lib.packet_parsing"), "ip2s", "ip2s")
  p.wrap(require("dup_query"), "get_picker", "dup.get_picker")
  p.wrap(require("dup_query"), "build_udp", "dup.build_udp")
  p.wrap(require("filter"), "decide_meta", "filter.decide_meta")
  p.wrap(require("filter"), "run_on_response", "filter.run_on_response")
  p.wrap(require("log"), "log_allow", "log.log_allow")
  p.wrap(require("log"), "log_info", "log.log_info")
  return nil
end
local apply_config
apply_config = function()
  local config = require("config")
  config.runtime = config.runtime or { }
  config.runtime.log_level = "INFO"
  config.runtime.benchmark = false
  config.runtime.pid_file = PROF_DIR .. "/custos.pid"
  config.metrics = config.metrics or { }
  config.second_opinion = config.second_opinion or { }
  config.second_opinion.resolvers = {
    VALIDATOR_IP
  }
  config.auth = config.auth or { }
  config.auth.sessions_file = SESSIONS_PATH
  config.auth.redirect_url = nil
  config.dns = config.dns or { }
  config.dns.upstream_retry = {
    enabled = true,
    max_attempts = 2,
    rcodes = {
      2,
      3,
      5
    },
    nxdomain_bad_ttl = 60,
    nxdomain_bad_max = 4096
  }
  config.ipc = config.ipc or { }
  config.ipc.pending_ttl = 5
  config.ipc.match_retry = {
    count = 5,
    sleep_ms = 20,
    budget_ms = 100
  }
  config.nft = config.nft or { }
  config.nft.family = "bridge"
  config.nft.family6 = "bridge"
  config.nft.table = "hotpath_bench_no_table"
  config.nft.ip_timeout = "2m"
  config.filter = config.filter or { }
  config.filter.allow_localnets = false
  if not (config.__hotpath_rules) then
    for _index_0 = 1, #BENCH_RULES do
      local r = BENCH_RULES[_index_0]
      config.filter.rules[#config.filter.rules + 1] = r
    end
    config.__hotpath_rules = true
  end
  return config
end
local write_sessions_file
write_sessions_file = function()
  local sessions = { }
  sessions[CLIENT_MAC] = {
    user = CLIENT_USER,
    expires = os.time() + 86400,
    mac = CLIENT_MAC,
    ips = {
      ipv4 = CLIENT_IP
    }
  }
  local auth_sessions = require("auth.sessions")
  return auth_sessions.write_sessions(sessions, SESSIONS_PATH)
end
local make_pipe
make_pipe = function(size)
  if size == nil then
    size = nil
  end
  local fds = ffi.new("int[2]")
  local rc = libc.pipe2(fds, O_NONBLOCK)
  if rc ~= 0 then
    error("pipe2() échoué")
  end
  if size then
    libc.fcntl(fds[1], F_SETPIPE_SZ, size)
  end
  return tonumber(fds[0]), tonumber(fds[1])
end
local drain_fd
drain_fd = function(fd)
  if not (fd and fd >= 0) then
    return nil
  end
  local buf = ffi.new("uint8_t[?]", 4096)
  while true do
    local n = libc.read(fd, buf, 4096)
    if not (n and n > 0) then
      break
    end
  end
  return nil
end
local read_line
read_line = function(fd)
  local buf = ffi.new("uint8_t[?]", 4096)
  local n = libc.read(fd, buf, 4096)
  if not (n and n > 0) then
    return nil
  end
  return (ffi.string(buf, tonumber(n))):match("^[^\n]*")
end
local setup
setup = function(opts)
  if opts == nil then
    opts = { }
  end
  os.execute("mkdir -p " .. tostring(PROF_DIR))
  local config = apply_config()
  install_stubs()
  config.gc = config.gc or { }
  local _list_0 = {
    "pause",
    "stepmul",
    "idle_step",
    "max_heap_mb"
  }
  for _index_0 = 1, #_list_0 do
    local key = _list_0[_index_0]
    local override = opts["gc_" .. key]
    if override ~= nil then
      config.gc[key] = override
    end
  end
  local gc_state = gc_tune.new(config.gc)
  gc_state.apply()
  write_sessions_file()
  local filter = require("filter")
  filter.load()
  local probes = nil
  if opts.stages then
    probes = stage_probe.new()
    install_probes(probes)
  end
  local qpipe_r, qpipe_w = make_pipe()
  local learn_r, learn_w = make_pipe()
  local ev_r, ev_w = make_pipe()
  local nft_r, nft_w = make_pipe(NFT_PIPE_BYTES)
  local sobus_r, sobus_w = make_pipe()
  local wq = require("worker_questions")
  wq.run(0, qpipe_w, learn_w, ev_w, nil)
  local ipc = require("ipc")
  local resp = require("worker_responses")
  resp.run(4, {
    question_response_rfd = qpipe_r,
    events_wfd = ev_w,
    nft_wfd = nft_w,
    chain_strip_enabled = false
  }, filter.get_rules().rules_metadata)
  resp._set_so_bus(nil, {
    sobus_w
  })
  resp.update_mac_clients({
    mac_str = CLIENT_MAC,
    ipv4 = true,
    ip_str = CLIENT_IP
  }, os.time())
  local set_payload
  set_payload = function(pkt)
    ffi.copy(payload_buf, pkt, #pkt)
    payload_len = #pkt
    return nil
  end
  local pkt_question = build_question_packet(QNAME_TLS)
  local pkt_question_vpn = build_question_packet(QNAME_VPN)
  local pkt_resp_a = build_response_packet(RESOLVER_IP, QNAME_TLS, ADDRS_TLS)
  local pkt_resp_b = build_response_packet(VALIDATOR_IP, QNAME_TLS, ADDRS_B)
  local pkt_resp_b8 = build_response_packet(VALIDATOR_IP, QNAME_TLS, ADDRS_VAL)
  local pkt_resp_vpn = build_response_packet(RESOLVER_IP, QNAME_VPN, ADDRS_VPN)
  local probe
  probe = function(pkt)
    set_payload(pkt)
    wq.handle_question(nil, nil, 1)
    local line = read_line(qpipe_r)
    local decoded = nil
    if line then
      local msg, err = ipc.decode_msg(line)
      if not (msg) then
        error("décodage IPC de la sonde impossible : " .. tostring(err))
      end
      decoded = msg
    end
    drain_fd(learn_r)
    drain_fd(ev_r)
    drain_fd(qpipe_r)
    return decoded
  end
  local msg_tls = probe(pkt_question)
  local msg_vpn = probe(pkt_question_vpn)
  if not (msg_tls) then
    error("sonde IPC vide (question TLS)")
  end
  if not (msg_vpn) then
    error("sonde IPC vide (question VPN)")
  end
  local ipc_line = ipc.encode_msg(msg_tls.txid, s2ip(CLIENT_IP), msg_tls.src_port, CLIENT_MAC_RAW, s2ip(RESOLVER_IP), false, msg_tls.reason, nil, msg_tls.rule_id, msg_tls.timeout, msg_tls.modifiers, msg_tls.response_rule_ids, nil)
  if not (ipc_line) then
    error("encode_msg a échoué")
  end
  set_payload(pkt_question)
  local packet_utils = require("packet_utils")
  local micro_tcp = packet_utils.new_dns_tcp_stream()
  local micro_p = { }
  for key, pkt in pairs({
    q = pkt_question,
    a = pkt_resp_a,
    b = pkt_resp_b8
  }) do
    local ip, l4, msg, raw, ihl = packet_utils.parse_dns_packet(pkt, micro_tcp)
    if not (msg) then
      error("parse du paquet micro " .. tostring(key) .. " impossible")
    end
    micro_p[key] = {
      ip = ip,
      l4 = l4,
      msg = msg,
      raw = raw,
      ihl = ihl
    }
  end
  local second_opinion = require("second_opinion")
  local dns_classify = require("dns_classify")
  local micro_so = second_opinion.new({
    resolvers = {
      VALIDATOR_IP
    },
    budget_ms = 80
  })
  local micro_vi = dns_classify.classify(micro_p.b.msg, micro_p.b.raw)
  local micro_override = {
    kind = "pass"
  }
  local micro_req = {
    domain = QNAME_TLS,
    src_ip = CLIENT_IP,
    mac = CLIENT_MAC,
    vlan = nil,
    ts = os.time(),
    user = CLIENT_USER
  }
  local micro_fields = {
    qname = QNAME_TLS,
    mac_src = CLIENT_MAC,
    src_ip = CLIENT_IP,
    dst_ip = RESOLVER_IP,
    vlan = nil,
    user = CLIENT_USER,
    af = "ipv4",
    reason = "Allowed by rule: Utilisateurs",
    rule = "r_utilisateurs"
  }
  local micro_msg = { }
  for k, v in pairs(msg_tls) do
    micro_msg[k] = v
  end
  micro_msg.txid = 0x7777
  ipc.set_pending(micro_msg, os.time)
  local micro_pipe_r, micro_pipe_w = make_pipe()
  return {
    config = config,
    filter = filter,
    wq = wq,
    resp = resp,
    qpipe_r = qpipe_r,
    qpipe_w = qpipe_w,
    learn_r = learn_r,
    ev_r = ev_r,
    ev_w = ev_w,
    nft_r = nft_r,
    nft_w = nft_w,
    sobus_r = sobus_r,
    sobus_w = sobus_w,
    micro_pipe_r = micro_pipe_r,
    micro_pipe_w = micro_pipe_w,
    micro_p = micro_p,
    micro_tcp = micro_tcp,
    micro_so = micro_so,
    micro_vi = micro_vi,
    micro_override = micro_override,
    micro_req = micro_req,
    micro_fields = micro_fields,
    micro_msg = micro_msg,
    set_payload = set_payload,
    pkt_question = pkt_question,
    pkt_question_vpn = pkt_question_vpn,
    pkt_resp_a = pkt_resp_a,
    pkt_resp_b = pkt_resp_b,
    pkt_resp_b8 = pkt_resp_b8,
    pkt_resp_vpn = pkt_resp_vpn,
    msg_tls = msg_tls,
    msg_vpn = msg_vpn,
    ipc_line = ipc_line,
    probes = probes,
    gc_state = gc_state,
    on_idle_q = run_queue_calls[1].opts and run_queue_calls[1].opts.on_idle,
    on_idle_r = run_queue_calls[2].opts and run_queue_calls[2].opts.on_idle,
    on_batch_end_q = run_queue_calls[1].opts and run_queue_calls[1].opts.on_batch_end,
    on_batch_end_r = run_queue_calls[2].opts and run_queue_calls[2].opts.on_batch_end,
    handle_question = run_queue_calls[1].callback,
    handle_response = run_queue_calls[2].callback
  }
end
local MICRO_CASES = {
  "micro_parse_q",
  "micro_parse_a",
  "micro_parse_b",
  "micro_decide",
  "micro_write_msg",
  "micro_encode_msg",
  "micro_build_udp",
  "micro_decode",
  "micro_makekey",
  "micro_add_line",
  "micro_parse_answers",
  "micro_strip",
  "micro_classify",
  "micro_encode_verdict",
  "micro_corr_key",
  "micro_ip2s",
  "micro_write_event",
  "micro_learn",
  "micro_user",
  "micro_get_pending",
  "micro_is_valid_timeout"
}
local build_micro_cases
build_micro_cases = function(s)
  local ipc = require("ipc")
  local packet_utils = require("packet_utils")
  local dns_ede = require("dns_ede")
  local disp = require("lib.dns_response")
  local nft_q = require("nft_queue")
  local second_opinion = require("second_opinion")
  local dns_classify = require("dns_classify")
  local dup = require("dup_query")
  local user_for_mac
  user_for_mac = require("auth.sessions").user_for_mac
  local add_ip4
  add_ip4 = require("nft_queue").add_ip4
  local write_msg
  write_msg = require("ipc").write_msg
  local ip2s
  ip2s = require("lib.packet_parsing").ip2s
  local ipc_hex = require("lib.ipc_hex")
  local drain_micro
  drain_micro = function()
    drain_fd(s.micro_pipe_r)
    drain_fd(s.nft_r)
    drain_fd(s.learn_r)
    drain_fd(s.ev_r)
    return drain_fd(s.sobus_r)
  end
  local micro
  micro = function(name, desc, fn, opts)
    if opts == nil then
      opts = nil
    end
    opts = opts or { }
    return {
      name = name,
      desc = desc,
      pkts = 1,
      labels = {
        name
      },
      steps = {
        function(i)
          return fn(i)
        end
      },
      finish = opts.finish,
      drain = opts.drain or drain_micro
    }
  end
  local q, a, b = s.micro_p.q, s.micro_p.a, s.micro_p.b
  local now_fn = require("log").now
  local add_line_step
  add_line_step = function(i)
    return (add_ip4(CLIENT_IP, "100.64.0.11", "r_utilisateurs", "660s", "1234:10.35.1.2:5353:10.35.1.1")) and 1 or 2
  end
  local wevent_step
  wevent_step = function(i)
    return (s.wq.write_event(s.micro_fields, true)) and 1 or 2
  end
  local learn_step
  learn_step = function(i)
    return (s.wq.write_learn_msg(q.ip.src, CLIENT_MAC_RAW)) and 1 or 2
  end
  return {
    micro("micro_parse_q", "parse_dns_packet (question client 78 o)", function()
      local ip, l4, msg = packet_utils.parse_dns_packet(s.pkt_question, s.micro_tcp)
      return (msg and 1) or 2
    end),
    micro("micro_parse_a", "parse_dns_packet (réponse A, 8 RR)", function()
      local ip, l4, msg = packet_utils.parse_dns_packet(s.pkt_resp_a, s.micro_tcp)
      return (msg and 1) or 2
    end),
    micro("micro_parse_b", "parse_dns_packet (réponse validateur B, 8 RR)", function()
      local ip, l4, msg = packet_utils.parse_dns_packet(s.pkt_resp_b8, s.micro_tcp)
      return (msg and 1) or 2
    end),
    micro("micro_decide", "filter.decide_meta (règle à second avis)", function()
      return (s.filter.decide_meta(s.micro_req)) and 1 or 2
    end),
    micro("micro_write_msg", "ipc.write_msg : encodage 14 champs + write", function()
      return (write_msg(s.micro_pipe_w, s.msg_tls.txid, q.ip.src, s.msg_tls.src_port, CLIENT_MAC_RAW, q.ip.dst, s.msg_tls.reason, nil, s.msg_tls.rule_id, s.msg_tls.timeout, s.msg_tls.modifiers, s.msg_tls.response_rule_ids, nil)) and 1 or 2
    end),
    micro("micro_encode_msg", "ipc.encode_msg seul (aucune écriture)", function()
      return #(ipc.encode_msg(s.msg_tls.txid, q.ip.src, s.msg_tls.src_port, CLIENT_MAC_RAW, q.ip.dst, false, s.msg_tls.reason, nil, s.msg_tls.rule_id, s.msg_tls.timeout, s.msg_tls.modifiers, s.msg_tls.response_rule_ids, nil))
    end),
    micro("micro_build_udp", "dup_query.build_udp (duplication validateur)", function()
      return #(dup.build_udp(q.ip, q.l4, q.raw, VALIDATOR_IP, s.pkt_question))
    end),
    micro("micro_decode", "ipc.decode_msg (14 champs)", function()
      return (ipc.decode_msg(s.ipc_line)) and 1 or 2
    end),
    micro("micro_makekey", "ipc.make_key (clé pending)", function()
      return #(ipc.make_key(TXID, CLIENT_IP, CLIENT_PORT, RESOLVER_IP))
    end),
    micro("micro_add_line", "nft_queue.add_ip4 : build_line + enqueue", add_line_step, {
      finish = function()
        return nft_q.get_last_seq()
      end
    }),
    micro("micro_parse_answers", "lib.dns_response.parse_answers (8 RR)", function()
      return #(disp.parse_answers(a.msg))
    end),
    micro("micro_strip", "dns_ede.patch_modified_dns (strip HTTPS + EDE)", function()
      local new_dns, mod = dns_ede.patch_modified_dns(a.raw, "Allowed by rule: Utilisateurs")
      return #new_dns + (mod and 1 or 0)
    end),
    micro("micro_classify", "dns_classify.classify (réponse validateur)", function()
      local v = dns_classify.classify(b.msg, b.raw)
      return (v and v.verdict == "pass") and 1 or 2
    end),
    micro("micro_encode_verdict", "second_opinion.encode_verdict (bus verdicts)", function()
      return #(second_opinion.encode_verdict(CLIENT_IP, TXID, QNAME_TLS, s.micro_override))
    end),
    micro("micro_corr_key", "second_opinion.corr_key (clé second avis)", function()
      return #(s.micro_so.corr_key(CLIENT_IP, TXID, QNAME_TLS))
    end),
    micro("micro_ip2s", "ip2s (4 octets → texte)", function()
      return #(ip2s(q.ip.src))
    end),
    micro("micro_write_event", "worker_questions.write_event (ligne TSV tamponnée)", wevent_step, {
      finish = function()
        return s.wq.flush_pipes()
      end
    }),
    micro("micro_learn", "worker_questions.write_learn_msg (22 o tamponnés)", learn_step, {
      finish = function()
        return s.wq.flush_pipes()
      end
    }),
    micro("micro_user", "auth.sessions.user_for_mac (session du client)", function()
      return (user_for_mac(CLIENT_MAC, CLIENT_IP, s.config.auth.sessions_file)) and 1 or 2
    end),
    micro("micro_get_pending", "ipc.get_pending_entry (hit)", function()
      return (ipc.get_pending_entry(0x7777, CLIENT_IP, CLIENT_PORT, RESOLVER_IP, now_fn)) and 1 or 2
    end),
    micro("micro_is_valid_timeout", "ipc_hex.is_valid_timeout (1×/ligne nft)", function()
      return (ipc_hex.is_valid_timeout("660s")) and 1 or 2
    end)
  }
end
local build_cases
build_cases = function(s)
  local ipc = require("ipc")
  local log_mod = require("log")
  local now_fn = log_mod.now
  local msg_tls = s.msg_tls
  local msg_vpn = s.msg_vpn
  local drain_all
  drain_all = function()
    drain_fd(s.qpipe_r)
    drain_fd(s.learn_r)
    drain_fd(s.ev_r)
    drain_fd(s.nft_r)
    return drain_fd(s.sobus_r)
  end
  local drain_cb
  drain_cb = function(msg)
    return s.resp.update_mac_clients(msg, now_fn())
  end
  local consume_tls
  consume_tls = function()
    ipc.consume(TXID, CLIENT_IP, CLIENT_PORT, RESOLVER_IP)
    return 1
  end
  return {
    {
      name = "question",
      desc = "handle_question : parse, décision filtre, ALLOW, IPC, événement, apprentissage, duplication",
      pkts = 1,
      pre = function(i)
        if s.on_idle_q then
          s.on_idle_q()
        end
        return s.set_payload(s.pkt_question)
      end,
      steps = {
        function(i)
          return s.handle_question(nil, nil, i)
        end
      },
      finish = function()
        if s.on_batch_end_q then
          return s.on_batch_end_q()
        end
      end,
      drain = drain_all
    },
    {
      name = "ipc_drain",
      desc = "tube question→réponse : écriture + lecture + décodage + insertion pending (1 message)",
      pkts = 1,
      steps = {
        function(i)
          libc.write(s.qpipe_w, s.ipc_line, #s.ipc_line)
          ipc.drain_pipe(s.qpipe_r, now_fn, drain_cb)
          ipc.consume(TXID, CLIENT_IP, CLIENT_PORT, RESOLVER_IP)
          return NF_ACCEPT
        end
      },
      drain = drain_all
    },
    {
      name = "response",
      desc = "handle_response sans second avis (r_ouverture_complete, 1 A, injection nft)",
      pkts = 1,
      pre = function(i)
        if s.on_idle_r then
          s.on_idle_r()
        end
        s.set_payload(s.pkt_resp_vpn)
        return ipc.set_pending(msg_vpn, now_fn)
      end,
      steps = {
        function(i)
          return s.handle_response(nil, nil, i)
        end
      },
      finish = function()
        return s.resp.flush_deferred()
      end,
      drain = drain_all
    },
    {
      name = "so_a",
      desc = "réponse A avec validate → parquage (sans déchargement)",
      pkts = 1,
      pre = function(i)
        if s.on_idle_r then
          s.on_idle_r()
        end
        s.set_payload(s.pkt_resp_a)
        return ipc.set_pending(msg_tls, now_fn)
      end,
      steps = {
        function(i)
          return s.handle_response(nil, nil, i)
        end
      },
      finish = function()
        return s.resp.flush_deferred()
      end,
      drain = drain_all
    },
    {
      name = "so_cycle",
      desc = "cycle second avis complet : réponse A parquée + réponse B validateur (8 A, 16 insertions nft)",
      pkts = 2,
      pre = function(i)
        if s.on_idle_r then
          s.on_idle_r()
        end
        s.set_payload(s.pkt_resp_a)
        return ipc.set_pending(msg_tls, now_fn)
      end,
      steps = {
        function(i)
          return s.handle_response(nil, nil, i)
        end,
        function(i)
          s.set_payload(s.pkt_resp_b)
          return s.handle_response(nil, nil, i)
        end
      },
      finish = function()
        return s.resp.flush_deferred()
      end,
      drain = drain_all
    },
    {
      name = "mixed_o2",
      desc = "cycle mixed complet AVEC second avis : question → A parquée → B validateur (classify, broadcast, déparquage, finalize 8 A)",
      pkts = 1,
      labels = {
        "q_handler",
        "q_flush",
        "r_a_park",
        "r_b_verdict",
        "r_flush"
      },
      pre = function(i)
        if s.on_idle_q then
          s.on_idle_q()
        end
        return s.set_payload(s.pkt_question)
      end,
      steps = {
        function(i)
          return s.handle_question(nil, nil, i)
        end,
        function(i)
          if s.on_batch_end_q then
            return s.on_batch_end_q()
          end
        end,
        function(i)
          s.set_payload(s.pkt_resp_a)
          return s.handle_response(nil, nil, i)
        end,
        function(i)
          s.set_payload(s.pkt_resp_b8)
          return s.handle_response(nil, nil, i)
        end,
        function(i)
          s.resp.flush_deferred()
          return nil
        end
      },
      drain = drain_all
    },
    {
      name = "mixed_plain",
      desc = "cycle mixed SANS second avis : question + réponse A du résolveur (1 A, injection nft)",
      pkts = 1,
      labels = {
        "q_handler",
        "q_flush",
        "r_a_finalize",
        "r_flush"
      },
      pre = function(i)
        if s.on_idle_q then
          s.on_idle_q()
        end
        return s.set_payload(s.pkt_question_vpn)
      end,
      steps = {
        function(i)
          return s.handle_question(nil, nil, i)
        end,
        function(i)
          if s.on_batch_end_q then
            return s.on_batch_end_q()
          end
        end,
        function(i)
          s.set_payload(s.pkt_resp_vpn)
          return s.handle_response(nil, nil, i)
        end,
        function(i)
          s.resp.flush_deferred()
          return nil
        end
      },
      drain = drain_all
    },
    {
      name = "setup_control",
      desc = "préparation seule des cas réponse (set_pending + consume) : incluse dans leurs mesures",
      pkts = 1,
      pre = function(i)
        return ipc.set_pending(msg_tls, now_fn)
      end,
      steps = {
        function(i)
          return consume_tls()
        end
      },
      drain = drain_all
    }
  }
end
local run_case
run_case = function(c, iters, chunk)
  local rets = { }
  local v0 = verdicts
  local total = 0
  local min_block = nil
  local heap_max = collectgarbage("count")
  local blocks = math.ceil(iters / chunk)
  for b = 1, blocks do
    local n = math.min(chunk, iters - (b - 1) * chunk)
    local t0 = os.clock()
    for i = 1, n do
      if c.pre then
        c.pre(i)
      end
      local _list_0 = c.steps
      for _index_0 = 1, #_list_0 do
        local step = _list_0[_index_0]
        local r = step(i)
        if r ~= nil then
          rets[r] = (rets[r] or 0) + 1
        end
      end
    end
    if c.finish then
      c.finish()
    end
    local t1 = os.clock()
    local dt = t1 - t0
    total = total + dt
    if n == chunk and (min_block == nil or dt < min_block) then
      min_block = dt
    end
    if c.drain then
      c.drain()
    end
    local heap = collectgarbage("count")
    if heap > heap_max then
      heap_max = heap
    end
  end
  return total, rets, verdicts - v0, min_block, heap_max
end
local measure_alloc
measure_alloc = function(c, iters)
  collectgarbage("collect")
  collectgarbage("stop")
  local before = collectgarbage("count")
  local blocks = math.ceil(iters / 64)
  for b = 1, blocks do
    local n = math.min(64, iters - (b - 1) * 64)
    for i = 1, n do
      if c.pre then
        c.pre(i)
      end
      local _list_0 = c.steps
      for _index_0 = 1, #_list_0 do
        local step = _list_0[_index_0]
        step(i)
      end
    end
    if c.finish then
      c.finish()
    end
    if c.drain then
      c.drain()
    end
  end
  local after = collectgarbage("count")
  collectgarbage("restart")
  collectgarbage("collect")
  return math.max(0, after - before) * 1024 / iters
end
local step_names
step_names = function(c)
  local out = { }
  for i = 1, #c.steps do
    out[i] = (c.labels and c.labels[i]) or "step" .. tostring(i)
  end
  return out
end
local measure_steps
measure_steps = function(c, iters, chunk, reps)
  local names = step_names(c)
  local best = { }
  for rep = 1, math.max(1, reps) do
    local acc = { }
    for i = 1, #names do
      acc[i] = 0
    end
    local blocks = math.ceil(iters / chunk)
    for b = 1, blocks do
      local n = math.min(chunk, iters - (b - 1) * chunk)
      for i = 1, n do
        if c.pre then
          c.pre(i)
        end
        for si, step in ipairs(c.steps) do
          local t0 = os.clock()
          step(i)
          local _update_0 = si
          acc[_update_0] = acc[_update_0] + (os.clock() - t0)
        end
      end
      if c.finish then
        c.finish()
      end
      if c.drain then
        c.drain()
      end
    end
    for si = 1, #names do
      if best[si] == nil or acc[si] < best[si] then
        best[si] = acc[si]
      end
    end
  end
  local out = { }
  for si = 1, #names do
    out[#out + 1] = {
      name = names[si],
      us = best[si] * 1e6 / iters
    }
  end
  return out
end
local measure_steps_alloc
measure_steps_alloc = function(c, iters, chunk)
  local names = step_names(c)
  local acc = { }
  for i = 1, #names do
    acc[i] = 0
  end
  for i = 1, chunk do
    if c.pre then
      c.pre(i)
    end
    local _list_0 = c.steps
    for _index_0 = 1, #_list_0 do
      local step = _list_0[_index_0]
      step(i)
    end
  end
  if c.finish then
    c.finish()
  end
  if c.drain then
    c.drain()
  end
  collectgarbage("collect")
  collectgarbage("stop")
  local blocks = math.ceil(iters / chunk)
  for b = 1, blocks do
    local n = math.min(chunk, iters - (b - 1) * chunk)
    for i = 1, n do
      if c.pre then
        c.pre(i)
      end
      for si, step in ipairs(c.steps) do
        local c0 = collectgarbage("count")
        step(i)
        local _update_0 = si
        acc[_update_0] = acc[_update_0] + ((collectgarbage("count")) - c0)
      end
    end
    if c.finish then
      c.finish()
    end
    if c.drain then
      c.drain()
    end
  end
  collectgarbage("restart")
  collectgarbage("collect")
  local out = { }
  for si = 1, #names do
    out[#out + 1] = {
      name = names[si],
      bytes = math.max(0, acc[si]) * 1024 / iters
    }
  end
  return out
end
local run_probed
run_probed = function(c, iters, chunk, p)
  p.reset()
  local blocks = math.ceil(iters / chunk)
  for b = 1, blocks do
    local n = math.min(chunk, iters - (b - 1) * chunk)
    for i = 1, n do
      if c.pre then
        c.pre(i)
      end
      local _list_0 = c.steps
      for _index_0 = 1, #_list_0 do
        local step = _list_0[_index_0]
        step(i)
      end
    end
    if c.finish then
      c.finish()
    end
    if c.drain then
      c.drain()
    end
  end
  return p.results(iters)
end
local profile_case
profile_case = function(c, mode, duration, chunk)
  local profile = require("jit.profile")
  local flat = { }
  local stacks = { }
  local vms = { }
  local fmt
  if mode == "l" then
    fmt = "l;"
  else
    fmt = "f;"
  end
  local cb
  cb = function(th, samples, vmst)
    vms[vmst] = (vms[vmst] or 0) + samples
    local ok, dumped = pcall(profile.dumpstack, th, fmt, 2)
    if ok and dumped and dumped ~= "" then
      local top = dumped:match("^[^;]+")
      flat[top] = (flat[top] or 0) + samples
      stacks[dumped] = (stacks[dumped] or 0) + samples
    end
    return nil
  end
  profile.start(mode, cb)
  local wall0 = os.time()
  local blocks = 0
  while os.time() - wall0 < duration do
    for i = 1, chunk do
      if c.pre then
        c.pre(i)
      end
      local _list_0 = c.steps
      for _index_0 = 1, #_list_0 do
        local step = _list_0[_index_0]
        step(i)
      end
    end
    if c.finish then
      c.finish()
    end
    if c.drain then
      c.drain()
    end
    blocks = blocks + 1
  end
  profile.stop()
  return {
    flat = flat,
    stacks = stacks,
    vms = vms,
    blocks,
    seconds = os.time() - wall0
  }
end
local parse_args
parse_args = function(argv)
  local o = {
    iters = 100000,
    chunk = 64,
    warmup = 5000,
    duration = 10,
    ["repeat"] = 3,
    profile = nil,
    only = nil,
    list = false,
    jit_v = nil,
    jit_dump = nil,
    jit_dump_mode = "t",
    gc_pause = nil,
    gc_stepmul = nil,
    gc_idle_step = nil,
    gc_max_heap_mb = nil,
    stages = false,
    no_steps = false,
    micro = false
  }
  local i = 1
  local next_val
  next_val = function()
    i = i + 1
    return argv[i]
  end
  while i <= #argv do
    local _exp_0 = argv[i]
    if "--iters" == _exp_0 then
      o.iters = tonumber(next_val())
    elseif "--chunk" == _exp_0 then
      o.chunk = tonumber(next_val())
    elseif "--warmup" == _exp_0 then
      o.warmup = tonumber(next_val())
    elseif "--duration" == _exp_0 then
      o.duration = tonumber(next_val())
    elseif "--repeat" == _exp_0 then
      o["repeat"] = tonumber(next_val())
    elseif "--profile" == _exp_0 then
      o.profile = next_val()
    elseif "--only" == _exp_0 then
      o.only = o.only or { }
      for n in (next_val()):gmatch("[^,]+") do
        o.only[#o.only + 1] = n
      end
    elseif "--micro" == _exp_0 then
      o.micro = true
    elseif "--list" == _exp_0 then
      o.list = true
    elseif "--jit-v" == _exp_0 then
      o.jit_v = next_val()
    elseif "--jit-dump" == _exp_0 then
      o.jit_dump = next_val()
    elseif "--jit-dump-mode" == _exp_0 then
      o.jit_dump_mode = next_val()
    elseif "--gc-pause" == _exp_0 then
      o.gc_pause = tonumber(next_val())
    elseif "--gc-stepmul" == _exp_0 then
      o.gc_stepmul = tonumber(next_val())
    elseif "--gc-idle-step" == _exp_0 then
      o.gc_idle_step = tonumber(next_val())
    elseif "--gc-max-heap" == _exp_0 then
      o.gc_max_heap_mb = tonumber(next_val())
    elseif "--stages" == _exp_0 then
      o.stages = true
    elseif "--no-steps" == _exp_0 then
      o.no_steps = true
    end
    i = i + 1
  end
  return o
end
local render_rets
render_rets = function(rets)
  local parts = { }
  for k, v in pairs(rets) do
    parts[#parts + 1] = tostring(k) .. "=" .. tostring(v)
  end
  table.sort(parts)
  return table.concat(parts, " ")
end
local render_verdicts
render_verdicts = function(r)
  if r.verdicts > 0 then
    return string.format("%.2f", r.verdicts / (r.iters * r.pkts))
  else
    return "0"
  end
end
local render_results
render_results = function(lines, results, o)
  lines[#lines + 1] = ""
  lines[#lines + 1] = "## Mesures (os.clock, GC actif, lots de " .. tostring(o.chunk) .. ", minimum de " .. tostring(o["repeat"]) .. " passages)"
  lines[#lines + 1] = ""
  lines[#lines + 1] = "| cas | iters | paquets | temps (s) | µs/paquet | µs/paquet (lot min) | µs/cycle | octets/paq (GC arrêté) | tas max (Kio) | retours | verdicts/paq |"
  lines[#lines + 1] = "|---|---|---|---|---|---|---|---|---|---|---|"
  for _index_0 = 1, #results do
    local r = results[_index_0]
    local pkts = r.iters * r.pkts
    local cycle
    if r.pkts > 1 then
      cycle = string.format("%.1f", r.secs * 1e6 / r.iters)
    else
      cycle = "—"
    end
    local min_us
    if r.min_block then
      min_us = string.format("%.1f", r.min_block * 1e6 / (o.chunk * r.pkts))
    else
      min_us = "—"
    end
    lines[#lines + 1] = string.format("| %s | %d | %d | %.3f | %.1f | %s | %s | %.0f | %.0f | `%s` | %s |", r.name, r.iters, pkts, r.secs, r.secs * 1e6 / pkts, min_us, cycle, r.alloc, r.heap_max or 0, render_rets(r.rets), render_verdicts(r))
  end
  return nil
end
local render_profile
render_profile = function(lines, name, mode, p)
  local total = 0
  for _, v in pairs(p.vms) do
    total = total + v
  end
  local col
  if mode == "l" then
    col = "ligne"
  else
    col = "fonction"
  end
  local vm_parts = { }
  for k, v in pairs(p.vms) do
    vm_parts[#vm_parts + 1] = tostring(k) .. "=" .. tostring(v) .. " (" .. tostring(format_pct(v, total)) .. "%)"
  end
  lines[#lines + 1] = ""
  lines[#lines + 1] = "### " .. tostring(name) .. " — jit.profile mode `" .. tostring(mode) .. "` (" .. tostring(p.seconds) .. " s, " .. tostring(total) .. " échantillons, " .. tostring(p.blocks) .. " lots)"
  lines[#lines + 1] = ""
  lines[#lines + 1] = "États VM : " .. table.concat(vm_parts, ", ")
  lines[#lines + 1] = ""
  lines[#lines + 1] = "| % | échantillons | " .. tostring(col) .. " |"
  lines[#lines + 1] = "|---|---|---|"
  local _list_0 = top_n(p.flat, 15)
  for _index_0 = 1, #_list_0 do
    local e = _list_0[_index_0]
    lines[#lines + 1] = string.format("| %s | %d | `%s` |", format_pct(e.count, total), e.count, e.key)
  end
  lines[#lines + 1] = ""
  lines[#lines + 1] = "Piles à deux niveaux (appelé ; appelant) :"
  lines[#lines + 1] = ""
  lines[#lines + 1] = "| % | échantillons | pile |"
  lines[#lines + 1] = "|---|---|---|"
  local _list_1 = top_n(p.stacks, 10)
  for _index_0 = 1, #_list_1 do
    local e = _list_1[_index_0]
    lines[#lines + 1] = string.format("| %s | %d | `%s` |", format_pct(e.count, total), e.count, e.key)
  end
  return nil
end
local MIX_O2_SHARE = 0.68
local render_steps
render_steps = function(lines, steps, o)
  if not (next(steps)) then
    return nil
  end
  lines[#lines + 1] = ""
  lines[#lines + 1] = "## Coût par étape (µs/requête, minimum de " .. tostring(math.max(1, o["repeat"])) .. " passages ; octets/requête GC arrêté)"
  lines[#lines + 1] = ""
  lines[#lines + 1] = "Chaque ligne est une étape du cycle réel du cas ; le total est celui du cycle mesuré sans instrumentation (tableau des mesures ci-dessus)."
  local order = { }
  for name in pairs(steps) do
    order[#order + 1] = name
  end
  table.sort(order)
  for _index_0 = 1, #order do
    local name = order[_index_0]
    local st = steps[name]
    local total_us = 0
    local _list_0 = st.time
    for _index_1 = 1, #_list_0 do
      local e = _list_0[_index_1]
      total_us = total_us + e.us
    end
    lines[#lines + 1] = ""
    lines[#lines + 1] = "### `" .. tostring(name) .. "` — total étapes " .. tostring(string.format("%.2f", total_us)) .. " µs/requête"
    lines[#lines + 1] = ""
    lines[#lines + 1] = "| étape | µs/requête | % | octets/requête |"
    lines[#lines + 1] = "|---|---|---|---|"
    for i, e in ipairs(st.time) do
      local bytes = st.alloc[i] and st.alloc[i].bytes or 0
      lines[#lines + 1] = string.format("| `%s` | %.2f | %s | %.0f |", e.name, e.us, format_pct(e.us, total_us), bytes)
    end
  end
  return nil
end
local render_stages
render_stages = function(lines, stages)
  if not (stages) then
    return nil
  end
  lines[#lines + 1] = ""
  lines[#lines + 1] = "## Sondes par fonction (option --stages, temps INCLUSIFS, cycle instrumenté)"
  lines[#lines + 1] = ""
  lines[#lines + 1] = "Le wrapper ajoute ~0,2-0,4 µs par appel : ces totaux sont gonflés, les parts relatives sont lisibles."
  for name, res in pairs(stages) do
    lines[#lines + 1] = ""
    lines[#lines + 1] = "### `" .. tostring(name) .. "`"
    lines[#lines + 1] = ""
    lines[#lines + 1] = "| sonde | µs/requête | µs/appel | appels/requête | octets/requête |"
    lines[#lines + 1] = "|---|---|---|---|---|"
    for _index_0 = 1, #res do
      local _continue_0 = false
      repeat
        local e = res[_index_0]
        if e.calls == 0 then
          _continue_0 = true
          break
        end
        lines[#lines + 1] = string.format("| `%s` | %.2f | %.3f | %.2f | %.0f |", e.label, e.us, e.us_call, e.calls_req, e.bytes)
        _continue_0 = true
      until true
      if not _continue_0 then
        break
      end
    end
  end
  return nil
end
local main
main = function(argv)
  local o = parse_args(argv)
  if o.list then
    io.write("cas : " .. tostring(table.concat(ALL_CASES, ", ")) .. "\n")
    return nil
  end
  local s = setup(o)
  local cases = build_cases(s)
  local _list_0 = build_micro_cases(s)
  for _index_0 = 1, #_list_0 do
    local c = _list_0[_index_0]
    cases[#cases + 1] = c
  end
  local by_name = { }
  for _index_0 = 1, #cases do
    local c = cases[_index_0]
    by_name[c.name] = c
  end
  if o.jit_v then
    require("jit.v").on(o.jit_v)
  end
  if o.jit_dump then
    require("jit.dump").on(o.jit_dump_mode, o.jit_dump)
  end
  local names = o.only or (o.micro and MICRO_CASES) or ALL_CASES
  local results = { }
  for _index_0 = 1, #names do
    local name = names[_index_0]
    local c = by_name[name]
    if not (c) then
      io.write("cas inconnu : " .. tostring(name) .. " (voir --list)\n")
      os.exit(1)
    end
    if o.warmup > 0 then
      run_case(c, o.warmup, o.chunk)
    end
    local best, best_rets, best_v, best_min = nil, nil, nil, nil
    local heap_peak = 0
    for rep = 1, math.max(1, o["repeat"]) do
      local secs, rets, v, min_block, heap_max = run_case(c, o.iters, o.chunk)
      if best == nil or secs < best then
        best, best_rets, best_v = secs, rets, v
      end
      if min_block and (best_min == nil or min_block < best_min) then
        best_min = min_block
      end
      if heap_max and heap_max > heap_peak then
        heap_peak = heap_max
      end
    end
    local alloc = measure_alloc(c, math.min(o.iters, 20000))
    results[#results + 1] = {
      name = c.name,
      pkts = c.pkts,
      iters = o.iters,
      ["repeat"] = math.max(1, o["repeat"]),
      secs = best,
      rets = best_rets,
      verdicts = best_v,
      alloc = alloc,
      min_block = best_min,
      heap_max = heap_peak
    }
  end
  local profiles = { }
  if o.profile then
    for _index_0 = 1, #names do
      local name = names[_index_0]
      profiles[name] = profile_case(by_name[name], o.profile, o.duration, o.chunk)
    end
  end
  local steps = { }
  if not (o.no_steps) then
    for _index_0 = 1, #names do
      local _continue_0 = false
      repeat
        local name = names[_index_0]
        local c = by_name[name]
        if not (c.labels and #c.labels == #c.steps) then
          _continue_0 = true
          break
        end
        if o.warmup > 0 then
          run_case(c, o.warmup, o.chunk)
        end
        steps[name] = {
          time = measure_steps(c, o.iters, o.chunk, math.max(1, o["repeat"])),
          alloc = measure_steps_alloc(c, o.chunk, o.chunk)
        }
        _continue_0 = true
      until true
      if not _continue_0 then
        break
      end
    end
  end
  local stages = nil
  if s.probes then
    stages = { }
    local _list_1 = {
      "mixed_o2",
      "mixed_plain"
    }
    for _index_0 = 1, #_list_1 do
      local name = _list_1[_index_0]
      local c = by_name[name]
      if c then
        stages[name] = run_probed(c, o.iters, o.chunk, s.probes)
      end
    end
  end
  if o.jit_v then
    require("jit.v").off()
  end
  if o.jit_dump then
    require("jit.dump").off()
  end
  local failures = { }
  for _index_0 = 1, #results do
    local r = results[_index_0]
    if r.name == "question" and (r.rets[NF_ACCEPT] or 0) ~= r.iters then
      failures[#failures + 1] = "question : " .. tostring(r.rets[NF_ACCEPT] or 0) .. " NF_ACCEPT pour " .. tostring(r.iters) .. " itérations"
    end
    if r.name == "response" and (r.rets[-1] or 0) ~= r.iters then
      failures[#failures + 1] = "response : " .. tostring(r.rets[-1] or 0) .. " verdicts différés pour " .. tostring(r.iters) .. " itérations"
    end
    if r.name == "so_a" and (r.rets[-1] or 0) ~= r.iters then
      failures[#failures + 1] = "so_a : " .. tostring(r.rets[-1] or 0) .. " parquages pour " .. tostring(r.iters) .. " itérations"
    end
    if r.name == "so_cycle" and r.verdicts ~= r.iters then
      failures[#failures + 1] = "so_cycle : " .. tostring(r.verdicts) .. " verdicts pour " .. tostring(r.iters) .. " cycles"
    end
    if r.name == "response" and r.verdicts ~= r.iters then
      failures[#failures + 1] = "response : " .. tostring(r.verdicts) .. " verdicts pour " .. tostring(r.iters) .. " paquets"
    end
    if r.name == "mixed_o2" then
      if not ((r.rets[NF_ACCEPT] or 0) == r.iters and (r.rets[-1] or 0) == r.iters and (r.rets[NF_DROP] or 0) == r.iters) then
        failures[#failures + 1] = "mixed_o2 : retours " .. tostring(render_rets(r.rets)) .. " (attendu 1=" .. tostring(r.iters) .. " -1=" .. tostring(r.iters) .. " 0=" .. tostring(r.iters) .. ")"
      end
      if r.verdicts ~= r.iters then
        failures[#failures + 1] = "mixed_o2 : " .. tostring(r.verdicts) .. " verdicts pour " .. tostring(r.iters) .. " requêtes"
      end
    end
    if r.name == "mixed_plain" then
      if not ((r.rets[NF_ACCEPT] or 0) == r.iters and (r.rets[-1] or 0) == r.iters) then
        failures[#failures + 1] = "mixed_plain : retours " .. tostring(render_rets(r.rets)) .. " (attendu 1=" .. tostring(r.iters) .. " -1=" .. tostring(r.iters) .. ")"
      end
      if r.verdicts ~= r.iters then
        failures[#failures + 1] = "mixed_plain : " .. tostring(r.verdicts) .. " verdicts pour " .. tostring(r.iters) .. " requêtes"
      end
    end
  end
  local lines = { }
  lines[#lines + 1] = "# Micro-banc hot path — " .. tostring(os.date("%Y-%m-%dT%H:%M:%S"))
  lines[#lines + 1] = ""
  lines[#lines + 1] = "- LuaJIT " .. tostring(jit.version) .. " / " .. tostring(jit.arch) .. " / " .. tostring(jit.os)
  lines[#lines + 1] = "- iters=" .. tostring(o.iters) .. ", repeat=" .. tostring(o["repeat"]) .. " (minimum retenu), chunk=" .. tostring(o.chunk) .. ", warmup=" .. tostring(o.warmup) .. ", profilage=" .. tostring(o.profile or "aucun") .. " (" .. tostring(o.duration) .. " s)"
  lines[#lines + 1] = string.format("- GC : pause=%d, stepmul=%d, idle_step=%d, max_heap_mb=%d (surcharges CLI appliquées dans setup)", s.gc_state.values.pause, s.gc_state.values.stepmul, s.gc_state.values.idle_step, s.gc_state.values.max_heap_mb)
  lines[#lines + 1] = "- paquet question : " .. tostring(#s.pkt_question) .. " o ; réponse A (8 A) : " .. tostring(#s.pkt_resp_a) .. " o ; réponse B : " .. tostring(#s.pkt_resp_b) .. " o"
  lines[#lines + 1] = "- duplication émise (stub raw_send) : " .. tostring(dup_sent) .. " ; verdicts posés (stub libnfq) : " .. tostring(verdicts)
  render_results(lines, results, o)
  render_steps(lines, steps, o)
  render_stages(lines, stages)
  local o2 = nil
  local plain = nil
  for _index_0 = 1, #results do
    local r = results[_index_0]
    if r.name == "mixed_o2" then
      o2 = r.secs * 1e6 / r.iters
    end
    if r.name == "mixed_plain" then
      plain = r.secs * 1e6 / r.iters
    end
  end
  if o2 and plain then
    lines[#lines + 1] = ""
    lines[#lines + 1] = string.format("**Total par requête `mixed` pondéré** (" .. tostring(MIX_O2_SHARE) .. " × `mixed_o2` + %s × `mixed_plain`) : **%.1f µs** (moyenne des passages ; minimum par lot : voir tableau).", 1 - MIX_O2_SHARE, MIX_O2_SHARE * o2 + (1 - MIX_O2_SHARE) * plain)
  end
  if next(profiles) then
    lines[#lines + 1] = ""
    lines[#lines + 1] = "## Profilage jit.profile"
    for _index_0 = 1, #names do
      local name = names[_index_0]
      local p = profiles[name]
      if p then
        render_profile(lines, name, o.profile, p)
      end
    end
  end
  if #failures > 0 then
    lines[#lines + 1] = ""
    lines[#lines + 1] = "## ÉCHECS DE VÉRIFICATION"
    for _index_0 = 1, #failures do
      local f = failures[_index_0]
      lines[#lines + 1] = "- " .. tostring(f)
    end
  end
  write_file(OUT_PATH, lines)
  local text = table.concat(lines, "\n") .. "\n"
  io.write(text)
  io.write("\n[hotpath] rapport : " .. tostring(OUT_PATH) .. "\n")
  if #failures > 0 then
    io.write("[hotpath] ÉCHEC DE VÉRIFICATION (" .. tostring(#failures) .. ")\n")
    os.exit(1)
  end
  return results
end
return {
  parse_args = parse_args,
  main = main,
  encode_name = encode_name,
  build_query = build_query,
  build_answer = build_answer,
  ipv4_udp = ipv4_udp,
  build_question_packet = build_question_packet,
  build_response_packet = build_response_packet,
  top_n = top_n,
  format_pct = format_pct,
  BENCH_RULES = BENCH_RULES,
  ALL_CASES = ALL_CASES,
  MICRO_CASES = MICRO_CASES,
  build_micro_cases = build_micro_cases,
  step_names = step_names,
  measure_steps = measure_steps,
  measure_steps_alloc = measure_steps_alloc,
  run_probed = run_probed,
  install_probes = install_probes,
  MIX_O2_SHARE = MIX_O2_SHARE
}
