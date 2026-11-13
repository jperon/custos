local config = require("config")
local to_hex
to_hex = require("lib.ipc_hex").to_hex
local setup_config
setup_config = function()
  config.runtime = config.runtime or { }
  config.runtime.log_level = "INFO"
  config.nft = config.nft or { }
  config.nft.family = "bridge"
  config.nft.family6 = "bridge"
  config.nft.table = "nftcpu_bench_no_table"
  config.nft.ip_timeout = "2m"
  return config
end
local ffi, libc
do
  local _obj_0 = require("ffi_defs")
  ffi, libc = _obj_0.ffi, _obj_0.libc
end
local _list_0 = {
  "int dup2(int oldfd, int newfd);",
  "int open(const char *pathname, int flags);"
}
for _index_0 = 1, #_list_0 do
  local decl = _list_0[_index_0]
  pcall(ffi.cdef, decl)
end
local OUT_DIR = "tmp/bench/nftcpu"
local CLOCK_MONOTONIC = 1
local O_WRONLY = 1
local O_NONBLOCK = 2048
local F_SETPIPE_SZ = 1031
local PIPE_BYTES = 1048576
local EAGAIN = 11
local WNOHANG = 1
local CLIENT = "10.35.1.2"
local MAC = "d8:d3:85:63:6b:27"
local RULE_ID = "r_utilisateurs"
local TIMEOUT = "660s"
local ADDRS = {
  "100.64.0.11",
  "100.64.0.12",
  "100.64.0.13",
  "100.64.0.14",
  "100.64.0.15",
  "100.64.0.16",
  "100.64.0.17",
  "100.64.0.18"
}
local ts_req = ffi.new("timespec_t[1]")
local sleep_req = ffi.new("timespec_t[1]")
local corr_buf = ffi.new("uint8_t[16]")
local monotonic_s
monotonic_s = function()
  libc.clock_gettime(CLOCK_MONOTONIC, ts_req)
  return tonumber(ts_req[0].tv_sec) + tonumber(ts_req[0].tv_nsec) / 1000000000
end
local sleep_ms
sleep_ms = function(ms)
  sleep_req[0].tv_sec = math.floor(ms / 1000)
  sleep_req[0].tv_nsec = (ms % 1000) * 1000000
  return libc.nanosleep(sleep_req, nil)
end
local corr_of
corr_of = function(i)
  corr_buf[0] = i % 256
  corr_buf[1] = math.floor(i / 256) % 256
  corr_buf[2] = math.floor(i / 65536) % 256
  corr_buf[3] = math.floor(i / 16777216) % 256
  return ffi.string(corr_buf, 16)
end
local build_line_fallback
build_line_fallback = function(kind, key, ip, rule_id, timeout, corr, item_seq, widx)
  return "v1|" .. kind .. "|" .. key .. "|" .. ip .. "|" .. to_hex(rule_id or "") .. "|" .. timeout .. "|" .. tostring(item_seq) .. "|" .. tostring(widx or -1) .. "|" .. to_hex(corr or "") .. "\n"
end
local build_turn
build_turn = function(nq, first_response, turns, lines_per_response, seq0)
  local line_of = nq.build_line or build_line_fallback
  local out = { }
  local seq = seq0
  for r = first_response, first_response + turns - 1 do
    local corr = corr_of(r)
    local widx = r % 2
    for k = 1, lines_per_response do
      local addr = ADDRS[(k - 1) % #ADDRS + 1]
      local kind = (k % 2 == 1) and "ip4" or "mac4"
      local key = (kind == "ip4") and CLIENT or MAC
      seq = seq + 1
      out[#out + 1] = line_of(kind, key, addr, RULE_ID, TIMEOUT, corr, seq, widx)
    end
  end
  return table.concat(out), seq
end
local write_all
write_all = function(fd, data)
  local n = #data
  local off = 0
  local ptr = ffi.cast("const char*", data)
  while off < n do
    local w = libc.write(fd, ptr + off, n - off)
    if w and w > 0 then
      off = off + w
    else
      local errno_p = libc.__errno_location()
      local errno
      if errno_p then
        errno = errno_p[0]
      else
        errno = 0
      end
      if errno ~= EAGAIN then
        return false
      end
      sleep_ms(1)
    end
  end
  return true
end
local stat_cpu_ticks
stat_cpu_ticks = function(pid)
  local fh = io.open("/proc/" .. pid .. "/stat")
  if not (fh) then
    return nil
  end
  local s = fh:read("*l")
  fh:close()
  if not (s) then
    return nil
  end
  local tail = s:match("%)%s+(.*)$")
  if not (tail) then
    return nil
  end
  local f = { }
  for tok in tail:gmatch("%S+") do
    f[#f + 1] = tok
  end
  local u = tonumber(f[12])
  local st = tonumber(f[13])
  if not (u and st) then
    return nil
  end
  return u + st
end
local clock_ticks
clock_ticks = function()
  local fh = io.popen("getconf CLK_TCK 2>/dev/null")
  local v = fh and fh:read("*l")
  if fh then
    fh:close()
  end
  return tonumber(v) or 100
end
local cpu_count
cpu_count = function()
  local fh = io.open("/proc/cpuinfo")
  if not (fh) then
    return 0
  end
  local n = 0
  for line in fh:lines() do
    if line:match("^processor%s*:") then
      n = n + 1
    end
  end
  fh:close()
  return n
end
local install_nft_stub
install_nft_stub = function()
  local stub = {
    run_cmd = function(cmd, opts)
      return true, nil
    end,
    cleanup = function()
      return nil
    end
  }
  package.loaded["nft"] = stub
  return stub
end
local apply_gc
apply_gc = function(o)
  local gc_tune = nil
  if not (o.legacy_gc) then
    local ok, mod = pcall(require, "lib.gc_tune")
    if ok then
      gc_tune = mod
    end
  end
  if gc_tune then
    config.gc = config.gc or { }
    local _list_1 = {
      "pause",
      "stepmul",
      "idle_step",
      "max_heap_mb"
    }
    for _index_0 = 1, #_list_1 do
      local key = _list_1[_index_0]
      local v = o["gc_" .. key]
      if v ~= nil then
        config.gc[key] = v
      end
    end
    local state = gc_tune.new(config.gc)
    state.apply()
    return state.values
  end
  local pause = o.gc_pause or config.runtime.gc_pause
  local stepmul = o.gc_stepmul or config.runtime.gc_stepmul
  if pause then
    collectgarbage("setpause", pause)
  end
  if stepmul then
    collectgarbage("setstepmul", stepmul)
  end
  return {
    pause = pause or 200,
    stepmul = stepmul or 200,
    idle_step = 0,
    max_heap_mb = 0
  }
end
local feed
feed = function(nq, wfd, o, turns, seq0)
  local t0 = monotonic_s()
  local deadline = t0 + o.duration
  local period = turns / o.qps
  local sent = 0
  local seq = seq0
  while true do
    local now = monotonic_s()
    if now >= deadline then
      break
    end
    local data
    data, seq = build_turn(nq, sent + 1, turns, o.lines, seq)
    write_all(wfd, data)
    sent = sent + turns
    local target = t0 + (sent / o.qps)
    local dt = target - monotonic_s()
    if dt > 0 then
      sleep_ms(dt * 1000)
    end
  end
  return sent, monotonic_s() - t0, seq
end
local measure_once
measure_once = function(wnft, nq, o, turns, hz)
  local fds = ffi.new("int[2]")
  local rc = libc.pipe2(fds, O_NONBLOCK)
  if rc ~= 0 then
    error("pipe2() échoué")
  end
  local rfd = tonumber(fds[0])
  local wfd = tonumber(fds[1])
  libc.fcntl(wfd, F_SETPIPE_SZ, PIPE_BYTES)
  local pid = libc.fork()
  if pid < 0 then
    error("fork() échoué")
  end
  if pid == 0 then
    libc.close(wfd)
    local devnull = libc.open("/dev/null", O_WRONLY)
    if devnull >= 0 then
      libc.dup2(devnull, 1)
      libc.dup2(devnull, 2)
      if devnull > 2 then
        libc.close(devnull)
      end
    end
    wnft.run(rfd)
    libc._exit(0)
  end
  libc.close(rfd)
  sleep_ms(250)
  local base = stat_cpu_ticks(pid)
  if not (base) then
    error("CPU enfant illisible")
  end
  local sent, feed_wall, seq = feed(nq, wfd, o, turns, 0)
  local after_feed = stat_cpu_ticks(pid) or base
  sleep_ms(o.idle * 1000)
  local after_idle = stat_cpu_ticks(pid) or after_feed
  libc.close(wfd)
  local final = after_idle
  local status = ffi.new("int[1]")
  while true do
    local last = stat_cpu_ticks(pid)
    if last then
      final = last
    end
    if libc.waitpid(pid, status, WNOHANG) == pid then
      break
    end
    sleep_ms(5)
  end
  return {
    sent = sent,
    feed_wall = feed_wall,
    seq = seq,
    feed_cpu_s = (after_feed - base) / hz,
    idle_cpu_s = (after_idle - after_feed) / hz,
    total_cpu_s = (final - base) / hz,
    turns_executed = math.ceil(sent / turns)
  }
end
local measure_alloc
measure_alloc = function(wnft, nq, o)
  local responses = o.alloc_responses
  local lines_per_response = o.lines
  local line_of = nq.build_line or build_line_fallback
  local lines = { }
  local seq = 0
  for r = 1, responses do
    local corr = corr_of(r)
    local widx = r % 2
    for k = 1, lines_per_response do
      local addr = ADDRS[(k - 1) % #ADDRS + 1]
      local kind = (k % 2 == 1) and "ip4" or "mac4"
      local key = (kind == "ip4") and CLIENT or MAC
      seq = seq + 1
      lines[#lines + 1] = line_of(kind, key, addr, RULE_ID, TIMEOUT, corr, seq, widx)
    end
  end
  local cache = wnft.new_cache()
  local pending = { }
  local ack_queue = { }
  collectgarbage("collect")
  collectgarbage("collect")
  collectgarbage("stop")
  local before = collectgarbage("count")
  for r = 1, responses do
    local base = (r - 1) * lines_per_response
    local pending_count = 0
    for k = 1, lines_per_response do
      local item = wnft.parse_line(lines[base + k])
      if item then
        ack_queue[#ack_queue + 1] = {
          widx = item.widx,
          seq = item.seq,
          corr = item.corr,
          rule_id = item.rule_id
        }
        if wnft.try_add_pending(pending, item, cache) then
          pending_count = pending_count + 1
        end
      end
    end
    if pending_count > 0 or #ack_queue > 0 then
      wnft.flush_batch(pending, ack_queue, { }, cache)
    end
  end
  local after = collectgarbage("count")
  collectgarbage("restart")
  collectgarbage("collect")
  return math.max(0, after - before) * 1024 / (responses * lines_per_response)
end
local parse_args
parse_args = function(argv)
  local o = {
    qps = 500,
    turns = {
      1,
      8
    },
    lines = 16,
    duration = 10,
    idle = 2,
    ["repeat"] = 3,
    alloc = false,
    cpu = true,
    legacy_gc = false,
    alloc_responses = 20000,
    tag = "run",
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
    if "--qps" == _exp_0 then
      o.qps = tonumber(next_val())
    elseif "--turns" == _exp_0 then
      o.turns = { }
      for t in (next_val()):gmatch("[^,]+") do
        o.turns[#o.turns + 1] = tonumber(t)
      end
    elseif "--lines" == _exp_0 then
      o.lines = tonumber(next_val())
    elseif "--duration" == _exp_0 then
      o.duration = tonumber(next_val())
    elseif "--idle" == _exp_0 then
      o.idle = tonumber(next_val())
    elseif "--repeat" == _exp_0 then
      o["repeat"] = tonumber(next_val())
    elseif "--alloc" == _exp_0 then
      o.alloc = true
    elseif "--no-cpu" == _exp_0 then
      o.cpu = false
    elseif "--legacy-gc" == _exp_0 then
      o.legacy_gc = true
    elseif "--alloc-responses" == _exp_0 then
      o.alloc_responses = tonumber(next_val())
    elseif "--tag" == _exp_0 then
      o.tag = next_val()
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
local fmt1
fmt1 = function(v)
  return string.format("%.1f", v)
end
local main
main = function(argv)
  local o = parse_args(argv)
  os.execute("mkdir -p " .. tostring(OUT_DIR))
  setup_config()
  local gc_values = apply_gc(o)
  install_nft_stub()
  local nq = require("nft_queue")
  local wnft = require("worker_nft")
  local hz = clock_ticks()
  local lines = { }
  lines[#lines + 1] = "# Banc CPU worker nft — " .. tostring(os.date("%Y-%m-%dT%H:%M:%S"))
  lines[#lines + 1] = ""
  lines[#lines + 1] = "- LuaJIT " .. tostring(jit.version) .. " / " .. tostring(jit.arch) .. " / " .. tostring(jit.os) .. ", " .. tostring(cpu_count()) .. " processeurs, HZ=" .. tostring(hz)
  lines[#lines + 1] = string.format("- GC appliqué avant fork : pause=%d, stepmul=%d, idle_step=%d, max_heap_mb=%d", gc_values.pause or 0, gc_values.stepmul or 0, gc_values.idle_step or 0, gc_values.max_heap_mb or 0)
  lines[#lines + 1] = string.format("- débit : %s réponses/s × %d lignes/réponse ; %s s de charge + %s s de temps mort ; %s répétition(s)", o.qps, o.lines, o.duration, o.idle, o["repeat"])
  lines[#lines + 1] = "- `nft.run_cmd` remplacé par un stub (`true`) : coût libnftables exclu, identique entre versions comparées"
  lines[#lines + 1] = ""
  if o.cpu then
    lines[#lines + 1] = "| tours | rép. | réponses | durées (s) | CPU charge (s) | CPU charge % | µs CPU/ligne | CPU temps mort % |"
    lines[#lines + 1] = "|---|---|---|---|---|---|---|---|"
    local samples = { }
    local _list_1 = o.turns
    for _index_0 = 1, #_list_1 do
      local turns = _list_1[_index_0]
      samples[turns] = { }
      for rep = 1, o["repeat"] do
        local r = measure_once(wnft, nq, o, turns, hz)
        local cpu_pct
        if r.feed_wall > 0 then
          cpu_pct = 100 * r.feed_cpu_s / r.feed_wall
        else
          cpu_pct = 0
        end
        local idle_pct
        if o.idle > 0 then
          idle_pct = 100 * r.idle_cpu_s / o.idle
        else
          idle_pct = 0
        end
        local us_line
        if r.sent > 0 then
          us_line = r.feed_cpu_s * 1e6 / (r.sent * o.lines)
        else
          us_line = 0
        end
        lines[#lines + 1] = string.format("| %d | %d | %d | %.2f | %.3f | %s | %s | %s |", turns, rep, r.sent, r.feed_wall, r.feed_cpu_s, fmt1(cpu_pct), fmt1(us_line), fmt1(idle_pct))
        samples[turns][#samples[turns] + 1] = {
          us_line = us_line,
          cpu_pct = cpu_pct,
          idle_pct = idle_pct,
          sent = r.sent,
          wall = r.feed_wall
        }
      end
    end
    local best = { }
    local _list_2 = o.turns
    for _index_0 = 1, #_list_2 do
      local _continue_0 = false
      repeat
        local turns = _list_2[_index_0]
        local list = samples[turns]
        if not (#list > 0) then
          _continue_0 = true
          break
        end
        table.sort(list, function(a, b)
          return a.us_line < b.us_line
        end)
        best[turns] = list[math.max(1, math.ceil(#list / 2))]
        _continue_0 = true
      until true
      if not _continue_0 then
        break
      end
    end
    lines[#lines + 1] = ""
    lines[#lines + 1] = "Médiane par taille de tour :"
    lines[#lines + 1] = ""
    lines[#lines + 1] = "| tours | réponses/s | tours/s | µs CPU/ligne | CPU charge % | CPU temps mort % |"
    lines[#lines + 1] = "|---|---|---|---|---|---|"
    local _list_3 = o.turns
    for _index_0 = 1, #_list_3 do
      local _continue_0 = false
      repeat
        local turns = _list_3[_index_0]
        local b = best[turns]
        if not (b) then
          _continue_0 = true
          break
        end
        local turns_per_s
        if b.wall > 0 then
          turns_per_s = b.sent / turns / b.wall
        else
          turns_per_s = 0
        end
        lines[#lines + 1] = string.format("| %d | %s | %s | %s | %s | %s |", turns, fmt1(o.qps), fmt1(turns_per_s), fmt1(b.us_line), fmt1(b.cpu_pct), fmt1(b.idle_pct))
        _continue_0 = true
      until true
      if not _continue_0 then
        break
      end
    end
    if #o.turns >= 2 then
      local t1, t8 = o.turns[1], o.turns[2]
      local b1, b8 = best[t1], best[t8]
      if b1 and b8 and b1.wall > 0 and b8.wall > 0 then
        local turns1 = b1.sent / t1 / b1.wall
        local turns8 = b8.sent / t8 / b8.wall
        local d_cpu = b1.cpu_pct / 100 - b8.cpu_pct / 100
        local d_turns = turns1 - turns8
        if d_turns > 0 then
          lines[#lines + 1] = ""
          lines[#lines + 1] = string.format("Coût d'un tour dérivé (%d vs %d tours) : **%s µs CPU/tour** (ΔCPU %s points, Δ%s tours/s).", t1, t8, fmt1(d_cpu / d_turns * 1e6), fmt1((b1.cpu_pct - b8.cpu_pct)), fmt1(d_turns))
        end
      end
    end
  end
  if o.alloc then
    local alloc = measure_alloc(wnft, nq, o)
    lines[#lines + 1] = ""
    lines[#lines + 1] = string.format("Allocation du chemin worker nft (parse + pending + flush, GC arrêté, %d réponses) : **%s octets/ligne**.", o.alloc_responses, fmt1(alloc))
  end
  local out_path = tostring(OUT_DIR) .. "/" .. tostring(o.tag) .. ".md"
  local fh = io.open(out_path, "w")
  if fh then
    fh:write(table.concat(lines, "\n") .. "\n")
    fh:close()
  end
  local text = table.concat(lines, "\n") .. "\n"
  io.write(text)
  io.write("\n[nftcpu] rapport : " .. tostring(out_path) .. "\n")
  return lines
end
return {
  main = main,
  parse_args = parse_args,
  build_turn = build_turn,
  build_line_fallback = build_line_fallback,
  corr_of = corr_of,
  stat_cpu_ticks = stat_cpu_ticks,
  apply_gc = apply_gc,
  install_nft_stub = install_nft_stub,
  measure_alloc = measure_alloc,
  measure_once = measure_once,
  feed = feed,
  setup_config = setup_config,
  CLIENT = CLIENT,
  MAC = MAC,
  RULE_ID = RULE_ID,
  TIMEOUT = TIMEOUT,
  ADDRS = ADDRS,
  write_all = write_all
}
