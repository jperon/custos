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
local log_info, log_warn, log_error, log_debug, set_action_prefix
do
  local _obj_0 = require("log")
  log_info, log_warn, log_error, log_debug, set_action_prefix = _obj_0.log_info, _obj_0.log_warn, _obj_0.log_error, _obj_0.log_debug, _obj_0.set_action_prefix
end
local ipparse_ip = require("ipparse.l3.ip")
local ipc_wfd = nil
local send_to_auth_server
send_to_auth_server = function(ip_version, ip_raw, mac_raw)
  if not (ipc_wfd and ipc_wfd >= 0) then
    return false
  end
  if not (ip_raw and mac_raw and #mac_raw == 6) then
    return false
  end
  local msg = ffi.new("uint8_t[22]")
  if ip_version == 4 then
    for i = 1, 4 do
      msg[i - 1] = ip_raw:byte(i)
    end
  else
    for i = 1, 16 do
      msg[i - 1] = ip_raw:byte(i)
    end
  end
  for i = 1, 6 do
    msg[16 + i - 1] = mac_raw:byte(i)
  end
  local n = libc.write(ipc_wfd, msg, 22)
  return n == 22
end
local handle_auth_packet
handle_auth_packet = function(qh_ptr, nfad, pkt_id)
  log_debug({
    action = "callback",
    pkt_id = pkt_id
  })
  local l2 = get_l2(nfad)
  if not (l2) then
    log_warn({
      action = "no_l2"
    })
    return NF_ACCEPT
  end
  local payload_ptr = ffi.new("unsigned char*[1]")
  local payload_len = libnfq.nfq_get_payload(nfad, payload_ptr)
  if payload_len <= 0 then
    log_warn({
      action = "no_payload",
      payload_len = payload_len
    })
    return NF_DROP
  end
  local raw = ffi.string(payload_ptr[0], payload_len)
  log_debug({
    action = "payload_len",
    len = payload_len
  })
  local ip, err = ipparse_ip.parse(raw, 1)
  if not (ip) then
    log_debug({
      action = "parse_failed",
      err = err
    })
    return NF_ACCEPT
  end
  local ip_raw = ip.src
  local mac_raw = l2.mac_raw
  if not (ip_raw and mac_raw) then
    log_warn({
      action = "missing_info"
    })
    return NF_ACCEPT
  end
  local ok = send_to_auth_server(ip.version, ip_raw, mac_raw)
  if not (ok) then
    log_warn({
      action = "ipc_failed"
    })
  end
  log_info({
    action = "processed",
    pkt_id = pkt_id
  })
  return NF_ACCEPT
end
local run
run = function(queue_num, wfd)
  set_action_prefix("auth_queue_")
  ipc_wfd = wfd
  log_info({
    action = "starting",
    queue = queue_num,
    ipc_fd = wfd
  })
  return run_queue(tonumber(queue_num), handle_auth_packet)
end
return {
  run = run
}
