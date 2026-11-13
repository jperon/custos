local ffi = require("ffi")
local gc_tune = require("lib.gc_tune")
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
  local qpipe_r, qpipe_w = make_pipe()
  local learn_r, learn_w = make_pipe()
  local ev_r, ev_w = make_pipe()
  local nft_r, nft_w = make_pipe(NFT_PIPE_BYTES)
  local resp_r, resp_w = make_pipe()
  local wq = require("worker_questions")
  wq.run(0, qpipe_w, learn_w, ev_w, nil)
  local ipc = require("ipc")
  local resp = require("worker_responses")
  resp.run(4, {
    question_response_rfd = resp_r,
    events_wfd = ev_w,
    nft_wfd = nft_w,
    chain_strip_enabled = false
  }, filter.get_rules().rules_metadata)
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
    set_payload = set_payload,
    pkt_question = pkt_question,
    pkt_question_vpn = pkt_question_vpn,
    pkt_resp_a = pkt_resp_a,
    pkt_resp_b = pkt_resp_b,
    pkt_resp_vpn = pkt_resp_vpn,
    msg_tls = msg_tls,
    msg_vpn = msg_vpn,
    ipc_line = ipc_line,
    gc_state = gc_state,
    on_idle_q = run_queue_calls[1].opts and run_queue_calls[1].opts.on_idle,
    on_idle_r = run_queue_calls[2].opts and run_queue_calls[2].opts.on_idle,
    on_batch_end_q = run_queue_calls[1].opts and run_queue_calls[1].opts.on_batch_end,
    on_batch_end_r = run_queue_calls[2].opts and run_queue_calls[2].opts.on_batch_end,
    handle_question = run_queue_calls[1].callback,
    handle_response = run_queue_calls[2].callback
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
    return drain_fd(s.nft_r)
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
        rets[r] = (rets[r] or 0) + 1
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
    gc_max_heap_mb = nil
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
      o.only = {
        next_val()
      }
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
local main
main = function(argv)
  local o = parse_args(argv)
  if o.list then
    io.write("cas : " .. tostring(table.concat(ALL_CASES, ", ")) .. "\n")
    return nil
  end
  local s = setup(o)
  local cases = build_cases(s)
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
  local names = o.only or ALL_CASES
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
  ALL_CASES = ALL_CASES
}
