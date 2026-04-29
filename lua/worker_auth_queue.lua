local ffi, libc, libnfq
do
  local _obj_0 = require("ffi_defs")
  ffi, libc, libnfq = _obj_0.ffi, _obj_0.libc, _obj_0.libnfq
end
local run_queue, NF_ACCEPT, NF_DROP
do
  local _obj_0 = require("nfq_loop")
  run_queue, NF_ACCEPT, NF_DROP = _obj_0.run_queue, _obj_0.NF_ACCEPT, _obj_0.NF_DROP
end
local get_l2
get_l2 = require("parse/ethernet").get_l2
local ndpi = require("parse/ndpi")
local log_info, log_warn, log_error, log_debug
do
  local _obj_0 = require("log")
  log_info, log_warn, log_error, log_debug = _obj_0.log_info, _obj_0.log_warn, _obj_0.log_error, _obj_0.log_debug
end
local ipc_wfd = nil
local send_to_auth_server
send_to_auth_server = function(ip_raw, mac_raw)
  if not (ipc_wfd and ipc_wfd >= 0) then
    return false
  end
  if not (ip_raw and (#ip_raw == 4 or #ip_raw == 16)) then
    return false
  end
  if not (mac_raw and #mac_raw == 6) then
    return false
  end
  local msg = ffi.new("uint8_t[22]")
  if #ip_raw == 4 then
    for i = 1, 4 do
      msg[i - 1] = ip_raw:byte(i)
    end
  else
    for i = 1, 16 do
      msg[i - 1] = ip_raw:byte(i)
    end
  end
  for i = 1, 6 do
    msg[15 + i] = mac_raw:byte(i)
  end
  local n = libc.write(ipc_wfd, msg, 22)
  return n == 22
end
local handle_auth_packet
handle_auth_packet = function(qh_ptr, nfad, pkt_id)
  local l2 = get_l2(nfad)
  local payload_ptr = ffi.new("unsigned char*[1]")
  local payload_len = libnfq.nfq_get_payload(nfad, payload_ptr)
  if payload_len <= 0 then
    return NF_DROP
  end
  local raw = ffi.string(payload_ptr[0], payload_len)
  local pkt = ndpi.parse_packet(raw)
  if not (pkt) then
    return NF_ACCEPT
  end
  local ip_raw = pkt.ip.src_ip_raw
  local mac_raw = l2.mac_raw
  if not (ip_raw and mac_raw) then
    log_warn({
      action = "auth_queue_missing_info",
      ip = pkt.ip.src_ip,
      mac = l2.mac_src
    })
    return NF_ACCEPT
  end
  local ok = send_to_auth_server(ip_raw, mac_raw)
  if not (ok) then
    log_warn({
      action = "auth_queue_ipc_failed",
      ip = pkt.ip.src_ip,
      mac = l2.mac_src
    })
  end
  log_debug({
    action = "auth_queue_accepted",
    ip = pkt.ip.src_ip,
    mac = l2.mac_src
  })
  return NF_ACCEPT
end
local run
run = function(queue_num, wfd)
  ipc_wfd = wfd
  ndpi.warmup()
  log_info({
    action = "auth_queue_starting",
    queue = queue_num,
    ipc_fd = wfd
  })
  run_queue(tonumber(queue_num), handle_auth_packet)
  return ndpi.cleanup()
end
return {
  run = run
}
