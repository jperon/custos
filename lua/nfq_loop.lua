local ffi, libc, libnfq
do
  local _obj_0 = require("ffi_defs")
  ffi, libc, libnfq = _obj_0.ffi, _obj_0.libc, _obj_0.libnfq
end
local config = require("config")
local nfq_rcvbuf = require("lib.nfq_rcvbuf")
local nfq_maxlen = require("lib.nfq_maxlen")
local lowmem = require("lib.lowmem")
local log_info, log_warn, log_error, log_debug, level_enabled
do
  local _obj_0 = require("log")
  log_info, log_warn, log_error, log_debug, level_enabled = _obj_0.log_info, _obj_0.log_warn, _obj_0.log_error, _obj_0.log_debug, _obj_0.level_enabled
end
local bit = require("bit")
local AF_BRIDGE = 7
local NFQNL_COPY_PACKET = 2
local NF_DROP = 0
local NF_ACCEPT = 1
local NF_REPEAT = 3
local EINTR = 4
local ENOBUFS = 105
local READ_BUF_SIZE = 65536
local MAX_BATCH_PKTS = 64
local VERDICT_DONE = -1
local CLOCK_REALTIME = 0
local _ts_ok, _ts_fn = pcall(function()
  return libnfq.nfq_get_timestamp
end)
local have_packet_timestamp = _ts_ok and _ts_fn ~= nil
local _age_ts = nil
local _age_tv = nil
local realtime_ms
realtime_ms = function()
  libc.clock_gettime(CLOCK_REALTIME, _age_ts)
  return tonumber(_age_ts[0].tv_sec) * 1000 + math.floor(tonumber(_age_ts[0].tv_nsec) / 1000000)
end
local packet_age_ms
packet_age_ms = function(nfad)
  if not (nfad and have_packet_timestamp) then
    return nil
  end
  if not (_age_ts) then
    _age_ts = ffi.new("timespec_t[1]")
    _age_tv = ffi.new("struct timeval[1]")
  end
  if libnfq.nfq_get_timestamp(nfad, _age_tv) ~= 0 then
    return nil
  end
  local pkt_ms = tonumber(_age_tv[0].tv_sec) * 1000 + math.floor(tonumber(_age_tv[0].tv_usec) / 1000)
  local age = realtime_ms() - pkt_ms
  return age < 0 and 0 or age
end
local run_queue
run_queue = function(queue_num, callback, opts)
  if opts == nil then
    opts = nil
  end
  log_info(function()
    return {
      action = "queue_open",
      queue = queue_num
    }
  end)
  log_debug(function()
    return {
      action = "queue_nfq_open_call",
      queue = queue_num
    }
  end)
  local h = libnfq.nfq_open()
  if h == nil then
    local errno = tonumber(ffi.C.__errno_location()[0])
    log_error(function()
      return {
        action = "queue_nfq_open_failed",
        queue = queue_num,
        errno = errno
      }
    end)
    error("nfq_open() échoué")
  end
  log_debug(function()
    return {
      action = "queue_bind_pf",
      queue = queue_num
    }
  end)
  libnfq.nfq_bind_pf(h, 2)
  libnfq.nfq_bind_pf(h, 10)
  libnfq.nfq_bind_pf(h, AF_BRIDGE)
  local fd = libnfq.nfq_fd(h)
  nfq_rcvbuf.configure(libc, fd, queue_num, (config.nfqueue and config.nfqueue.rcvbuf), (lowmem.detect((config.runtime or { }))))
  local qh_box = ffi.new("nfq_q_handle*[1]")
  log_debug(function()
    return {
      action = "queue_callback_setup",
      queue = queue_num
    }
  end)
  local c_callback = ffi.cast("nfq_callback", function(qh, nfmsg, nfad, data)
    local raw_hdr = libnfq.nfq_get_msg_packet_hdr(nfad)
    local pkt_id = libc.ntohl(raw_hdr.packet_id)
    local ok, verdict = pcall(callback, qh_box[0], nfad, pkt_id)
    if not (ok) then
      log_error(function()
        return {
          action = "callback_exception",
          err = tostring(verdict),
          queue = queue_num
        }
      end)
      verdict = NF_DROP
    end
    if verdict ~= VERDICT_DONE then
      libnfq.nfq_set_verdict(qh_box[0], pkt_id, verdict, 0, nil)
    end
    return 0
  end)
  log_debug(function()
    return {
      action = "queue_create_queue_call",
      queue = queue_num
    }
  end)
  local qh = libnfq.nfq_create_queue(h, queue_num, c_callback, nil)
  if qh == nil then
    local errno = tonumber(ffi.C.__errno_location()[0])
    log_error(function()
      return {
        action = "queue_create_queue_failed",
        queue = queue_num,
        errno = errno
      }
    end)
    error("nfq_create_queue(" .. tostring(queue_num) .. ") échoué")
  end
  qh_box[0] = qh
  nfq_maxlen.configure(libnfq, libc, qh, queue_num, (config.nfqueue and config.nfqueue.maxlen), (lowmem.detect((config.runtime or { }))))
  log_debug(function()
    return {
      action = "queue_set_mode_call",
      queue = queue_num
    }
  end)
  libnfq.nfq_set_mode(qh, NFQNL_COPY_PACKET, READ_BUF_SIZE)
  local buf = ffi.new("char[65536]")
  log_info(function()
    return {
      action = "queue_listening",
      queue = queue_num,
      pid = tonumber(ffi.C.getpid and ffi.C.getpid() or 0)
    }
  end)
  local idle_ms = opts and opts.idle_ms
  local on_idle = opts and opts.on_idle
  local on_batch_end = opts and opts.on_batch_end
  local extra_rfds = (opts and opts.extra_rfds) or { }
  local on_extra_ready = opts and opts.on_extra_ready
  local n_extra = #extra_rfds
  local pfd = nil
  if (idle_ms and idle_ms > 0) or n_extra > 0 then
    pfd = ffi.new("struct pollfd[?]", 1 + n_extra)
    pfd[0].fd = fd
    pfd[0].events = 1
    for i = 1, n_extra do
      pfd[i].fd = extra_rfds[i]
      pfd[i].events = 1
    end
  end
  local pfd_drain = nil
  if on_batch_end then
    pfd_drain = ffi.new("struct pollfd[1]")
    pfd_drain[0].fd = fd
    pfd_drain[0].events = 1
  end
  local enobufs_total = 0
  local reading = false
  local read_packets
  read_packets = function(limit)
    limit = limit or MAX_BATCH_PKTS
    if reading or limit <= 0 then
      return 0
    end
    reading = true
    local n = 0
    while n < limit do
      pfd_drain[0].revents = 0
      local dr = libc.poll(pfd_drain, 1, 0)
      if dr <= 0 then
        break
      end
      local rv2 = libc.read(fd, buf, READ_BUF_SIZE)
      if rv2 > 0 then
        libnfq.nfq_handle_packet(h, buf, tonumber(rv2))
        n = n + 1
      else
        if rv2 < 0 then
          local en2 = libc.__errno_location()[0]
          if en2 == ENOBUFS then
            enobufs_total = enobufs_total + 1
            if enobufs_total == 1 or enobufs_total % 256 == 0 then
              log_warn(function()
                return {
                  action = "queue_read_enobufs",
                  queue = queue_num,
                  total = enobufs_total
                }
              end)
            end
          end
        end
        break
      end
    end
    reading = false
    return n
  end
  while true do
    local _continue_0 = false
    repeat
      if pfd then
        if on_idle then
          on_idle()
        end
        local poll_timeout
        if idle_ms and idle_ms > 0 then
          poll_timeout = idle_ms
        else
          poll_timeout = -1
        end
        local pr = libc.poll(pfd, 1 + n_extra, poll_timeout)
        if pr == 0 then
          _continue_0 = true
          break
        elseif pr < 0 then
          local en = libc.__errno_location()[0]
          if en == EINTR then
            _continue_0 = true
            break
          end
          log_warn(function()
            return {
              action = "queue_poll_error",
              queue = queue_num,
              errno = en
            }
          end)
          break
        else
          if n_extra > 0 then
            local netlink_rev = pfd[0].revents
            local netlink_ready = bit.band(netlink_rev, 1) ~= 0
            if not (netlink_ready) then
              if bit.band(netlink_rev, 0x38) ~= 0 then
                log_warn(function()
                  return {
                    action = "queue_poll_error",
                    queue = queue_num,
                    revents = netlink_rev
                  }
                end)
                break
              end
              local extra_ready = false
              for i = 1, n_extra do
                local rev = pfd[i].revents
                if rev ~= 0 and bit.band(rev, 1) == 0 then
                  pfd[i].fd = -1
                elseif bit.band(rev, 1) ~= 0 then
                  extra_ready = true
                end
              end
              if extra_ready and on_extra_ready then
                on_extra_ready()
              end
              _continue_0 = true
              break
            end
          end
        end
      end
      if level_enabled("DEBUG") then
        log_debug(function()
          return {
            action = "queue_read_call",
            queue = queue_num
          }
        end)
      end
      local rv = libc.read(fd, buf, READ_BUF_SIZE)
      if rv > 0 then
        if level_enabled("DEBUG") then
          log_debug(function()
            return {
              action = "queue_handle_packet",
              queue = queue_num,
              rv = rv
            }
          end)
        end
        libnfq.nfq_handle_packet(h, buf, tonumber(rv))
        if on_batch_end then
          read_packets(MAX_BATCH_PKTS - 1)
          on_batch_end(read_packets)
        end
      elseif rv == 0 then
        log_warn(function()
          return {
            action = "queue_read_eof",
            queue = queue_num
          }
        end)
        break
      else
        local en = libc.__errno_location()[0]
        if en == EINTR then
          log_debug(function()
            return {
              action = "queue_read_eintr",
              queue = queue_num
            }
          end)
          break
        end
        if en == ENOBUFS then
          enobufs_total = enobufs_total + 1
          if enobufs_total == 1 or enobufs_total % 256 == 0 then
            log_warn(function()
              return {
                action = "queue_read_enobufs",
                queue = queue_num,
                total = enobufs_total
              }
            end)
          end
          _continue_0 = true
          break
        end
        log_warn(function()
          return {
            action = "queue_read_error",
            queue = queue_num,
            errno = en
          }
        end)
        break
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  log_info(function()
    return {
      action = "queue_closed",
      queue = queue_num
    }
  end)
  if on_batch_end then
    on_batch_end()
  end
  libnfq.nfq_destroy_queue(qh)
  libnfq.nfq_close(h)
  return c_callback:free()
end
local set_verdict_marked
set_verdict_marked = function(qh_ptr, pkt_id, verdict, mark, payload)
  if payload == nil then
    payload = nil
  end
  if payload then
    local ptr = ffi.cast("const unsigned char*", payload)
    local rc = libnfq.nfq_set_verdict2(qh_ptr, pkt_id, verdict, mark, #payload, ptr)
    return rc >= 0 and 0 or rc
  end
  local rc = libnfq.nfq_set_verdict2(qh_ptr, pkt_id, verdict, mark, 0, nil)
  return rc >= 0 and 0 or rc
end
return {
  run_queue = run_queue,
  NF_ACCEPT = NF_ACCEPT,
  NF_DROP = NF_DROP,
  VERDICT_DONE = VERDICT_DONE,
  set_verdict_marked = set_verdict_marked,
  MAX_BATCH_PKTS = MAX_BATCH_PKTS,
  packet_age_ms = packet_age_ms,
  have_packet_timestamp = have_packet_timestamp
}
