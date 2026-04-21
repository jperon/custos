local ffi, libc, libnfq
do
  local _obj_0 = require("ffi_defs")
  ffi, libc, libnfq = _obj_0.ffi, _obj_0.libc, _obj_0.libnfq
end
local AF_INET, AF_INET6
do
  local _obj_0 = require("config")
  AF_INET, AF_INET6 = _obj_0.AF_INET, _obj_0.AF_INET6
end
local log_info, log_error
do
  local _obj_0 = require("log")
  log_info, log_error = _obj_0.log_info, _obj_0.log_error
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
  local h = libnfq.nfq_open()
  if h == nil then
    error("nfq_open() échoué")
  end
  libnfq.nfq_bind_pf(h, AF_INET)
  libnfq.nfq_bind_pf(h, AF_INET6)
  libnfq.nfq_bind_pf(h, AF_BRIDGE)
  local qh_box = ffi.new("nfq_q_handle*[1]")
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
  local qh = libnfq.nfq_create_queue(h, queue_num, c_callback, nil)
  if qh == nil then
    error("nfq_create_queue(" .. tostring(queue_num) .. ") échoué")
  end
  qh_box[0] = qh
  libnfq.nfq_set_mode(qh, NFQNL_COPY_PACKET, READ_BUF_SIZE)
  local fd = libnfq.nfq_fd(h)
  local buf = ffi.new("char[65536]")
  log_info({
    action = "queue_listening",
    queue = queue_num,
    pid = tonumber(ffi.C.getpid and ffi.C.getpid() or 0)
  })
  while true do
    local rv = libc.read(fd, buf, READ_BUF_SIZE)
    if rv > 0 then
      libnfq.nfq_handle_packet(h, buf, tonumber(rv))
    elseif rv == 0 then
      break
    else
      if libc.__errno_location()[0] == EINTR then
        break
      end
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
