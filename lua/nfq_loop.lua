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
local READ_BUF_SIZE = 65536
local VERDICT_DONE = -1
local run_queue
run_queue = function(queue_num, callback)
  log_info({
    action = "queue_open",
    queue = queue_num
  })
  log_debug({
    action = "queue_nfq_open_call",
    queue = queue_num
  })
  local h = libnfq.nfq_open()
  if h == nil then
    local errno = tonumber(ffi.C.__errno_location()[0])
    log_error({
      action = "queue_nfq_open_failed",
      queue = queue_num,
      errno = errno
    })
    error("nfq_open() échoué")
  end
  log_debug({
    action = "queue_bind_pf",
    queue = queue_num
  })
  libnfq.nfq_bind_pf(h, 2)
  libnfq.nfq_bind_pf(h, 10)
  libnfq.nfq_bind_pf(h, AF_BRIDGE)
  local qh_box = ffi.new("nfq_q_handle*[1]")
  log_debug({
    action = "queue_callback_setup",
    queue = queue_num
  })
  local c_callback = ffi.cast("nfq_callback", function(qh, nfmsg, nfad, data)
    local raw_hdr = libnfq.nfq_get_msg_packet_hdr(nfad)
    local pkt_id = libc.ntohl(raw_hdr.packet_id)
    local ok, verdict = pcall(callback, qh_box[0], nfad, pkt_id)
    if not (ok) then
      log_error({
        action = "callback_exception",
        err = tostring(verdict),
        queue = queue_num
      })
      verdict = NF_DROP
    end
    if verdict ~= VERDICT_DONE then
      libnfq.nfq_set_verdict(qh_box[0], pkt_id, verdict, 0, nil)
    end
    return 0
  end)
  log_debug({
    action = "queue_create_queue_call",
    queue = queue_num
  })
  local qh = libnfq.nfq_create_queue(h, queue_num, c_callback, nil)
  if qh == nil then
    local errno = tonumber(ffi.C.__errno_location()[0])
    log_error({
      action = "queue_create_queue_failed",
      queue = queue_num,
      errno = errno
    })
    error("nfq_create_queue(" .. tostring(queue_num) .. ") échoué")
  end
  qh_box[0] = qh
  log_debug({
    action = "queue_set_mode_call",
    queue = queue_num
  })
  libnfq.nfq_set_mode(qh, NFQNL_COPY_PACKET, READ_BUF_SIZE)
  local fd = libnfq.nfq_fd(h)
  local buf = ffi.new("char[65536]")
  log_info({
    action = "queue_listening",
    queue = queue_num,
    pid = tonumber(ffi.C.getpid and ffi.C.getpid() or 0)
  })
  while true do
    log_debug({
      action = "queue_read_call",
      queue = queue_num
    })
    local rv = libc.read(fd, buf, READ_BUF_SIZE)
    if rv > 0 then
      log_debug({
        action = "queue_handle_packet",
        queue = queue_num,
        rv = rv
      })
      libnfq.nfq_handle_packet(h, buf, tonumber(rv))
    elseif rv == 0 then
      log_warn({
        action = "queue_read_eof",
        queue = queue_num
      })
      break
    else
      local en = libc.__errno_location()[0]
      if en == EINTR then
        log_debug({
          action = "queue_read_eintr",
          queue = queue_num
        })
        break
      end
      log_warn({
        action = "queue_read_error",
        queue = queue_num,
        errno = en
      })
      break
    end
  end
  log_info({
    action = "queue_closed",
    queue = queue_num
  })
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
