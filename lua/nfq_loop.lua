local ffi, libc, libnfq
do
  local _obj_0 = require("ffi_defs")
  ffi, libc, libnfq = _obj_0.ffi, _obj_0.libc, _obj_0.libnfq
end
local config = require("config")
local log_info, log_warn, log_error, log_debug
do
  local _obj_0 = require("log")
  log_info, log_warn, log_error, log_debug = _obj_0.log_info, _obj_0.log_warn, _obj_0.log_error, _obj_0.log_debug
end
local AF_BRIDGE = 7
local NFQNL_COPY_PACKET = 2
local NF_DROP = 0
local NF_ACCEPT = 1
local NF_REPEAT = 3
local EINTR = 4
local ENOBUFS = 105
local READ_BUF_SIZE = 65536
local VERDICT_DONE = -1
local run_queue
run_queue = function(queue_num, callback)
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
  log_debug(function()
    return {
      action = "queue_set_mode_call",
      queue = queue_num
    }
  end)
  libnfq.nfq_set_mode(qh, NFQNL_COPY_PACKET, READ_BUF_SIZE)
  local fd = libnfq.nfq_fd(h)
  local buf = ffi.new("char[65536]")
  log_info(function()
    return {
      action = "queue_listening",
      queue = queue_num,
      pid = tonumber(ffi.C.getpid and ffi.C.getpid() or 0)
    }
  end)
  local enobufs_total = 0
  while true do
    local _continue_0 = false
    repeat
      log_debug(function()
        return {
          action = "queue_read_call",
          queue = queue_num
        }
      end)
      local rv = libc.read(fd, buf, READ_BUF_SIZE)
      if rv > 0 then
        log_debug(function()
          return {
            action = "queue_handle_packet",
            queue = queue_num,
            rv = rv
          }
        end)
        libnfq.nfq_handle_packet(h, buf, tonumber(rv))
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
  libnfq.nfq_destroy_queue(qh)
  libnfq.nfq_close(h)
  return c_callback:free()
end
return {
  run_queue = run_queue,
  NF_ACCEPT = NF_ACCEPT,
  NF_DROP = NF_DROP,
  VERDICT_DONE = VERDICT_DONE
}
