local ffi, libc, libnfq
do
  local _obj_0 = require("ffi_defs")
  ffi, libc, libnfq = _obj_0.ffi, _obj_0.libc, _obj_0.libnfq
end
local QUEUE_CAPTIVE, NFQ_BRIDGE_MODE
do
  local _obj_0 = require("config")
  QUEUE_CAPTIVE, NFQ_BRIDGE_MODE = _obj_0.QUEUE_CAPTIVE, _obj_0.NFQ_BRIDGE_MODE
end
local parse_syn, parse_syn_ip, build_response_frames, open_raw_socket, send_frame, open_dgram_socket, send_packet
do
  local _obj_0 = require("parse/tcp")
  parse_syn, parse_syn_ip, build_response_frames, open_raw_socket, send_frame, open_dgram_socket, send_packet = _obj_0.parse_syn, _obj_0.parse_syn_ip, _obj_0.build_response_frames, _obj_0.open_raw_socket, _obj_0.send_frame, _obj_0.open_dgram_socket, _obj_0.send_packet
end
local run_queue, NF_ACCEPT, NF_DROP
do
  local _obj_0 = require("nfq_loop")
  run_queue, NF_ACCEPT, NF_DROP = _obj_0.run_queue, _obj_0.NF_ACCEPT, _obj_0.NF_DROP
end
local log_info, log_warn, log_error
do
  local _obj_0 = require("log")
  log_info, log_warn, log_error = _obj_0.log_info, _obj_0.log_warn, _obj_0.log_error
end
local raw_fd = nil
local ifindex = nil
local redirect_url = nil
local handle_syn
handle_syn = function(qh_ptr, nfad, pkt_id)
  local payload_ptr = ffi.new("unsigned char*[1]")
  local payload_len = libnfq.nfq_get_payload(nfad, payload_ptr)
  if payload_len <= 0 then
    return NF_DROP
  end
  local raw = ffi.string(payload_ptr[0], payload_len)
  local syn
  if NFQ_BRIDGE_MODE then
    syn = parse_syn(raw)
  else
    syn = parse_syn_ip(raw)
  end
  if not (syn) then
    log_warn({
      action = "q2_parse_failed",
      len = payload_len
    })
    return NF_DROP
  end
  local send
  if NFQ_BRIDGE_MODE then
    send = function(f)
      return send_frame(raw_fd, f, ifindex)
    end
  else
    send = function(f)
      return send_packet(raw_fd, f, ifindex)
    end
  end
  local ok, err = pcall(function()
    local f1, f2, f3 = build_response_frames(syn, redirect_url, NFQ_BRIDGE_MODE)
    send(f1)
    send(f2)
    return send(f3)
  end)
  if ok then
    local fields = {
      action = "captive_redirect_q2",
      ip = syn.ip_src,
      sport = syn.sport,
      vlan = tonumber(libnfq.nfq_get_nfmark(nfad)) or nil,
      url = redirect_url
    }
    if syn.eth_src then
      fields.mac = string.format("%02x:%02x:%02x:%02x:%02x:%02x", syn.eth_src:byte(1), syn.eth_src:byte(2), syn.eth_src:byte(3), syn.eth_src:byte(4), syn.eth_src:byte(5), syn.eth_src:byte(6))
    end
    log_info(fields)
  else
    log_warn({
      action = "q2_send_failed",
      err = tostring(err, {
        ip = syn.ip_src
      })
    })
  end
  return NF_DROP
end
local run
run = function(auth_cfg)
  auth_cfg = auth_cfg or { }
  local ifname = auth_cfg.bridge_ifname or os.getenv("BRIDGE_IFNAME") or "br"
  local https_port = auth_cfg.port or 33443
  local local_ip = auth_cfg.captive_ip or os.getenv("CAPTIVE_IP") or "127.0.0.1"
  local ok_sock, socket = pcall(require, "socket")
  if ok_sock then
    pcall(function()
      local u = socket.udp()
      pcall(function()
        return u:connect("8.8.8.8", 80)
      end)
      local ip, _ = u:getsockname()
      u:close()
      if ip and ip ~= "" and ip ~= "0.0.0.0" then
        local_ip = ip
      end
    end)
  end
  local host_part = local_ip:find(":", 1, true) and "[" .. tostring(local_ip) .. "]" or local_ip
  redirect_url = "https://" .. tostring(host_part) .. ":" .. tostring(https_port) .. "/"
  local open_fn
  if NFQ_BRIDGE_MODE then
    open_fn = open_raw_socket
  else
    open_fn = open_dgram_socket
  end
  local fd, err = open_fn(ifname)
  if not (fd) then
    log_error({
      action = "q2_socket_failed",
      err = err,
      ifname = ifname
    })
    return 
  end
  raw_fd = fd
  ifindex = tonumber(ffi.C.if_nametoindex(ifname))
  if ifindex == 0 then
    log_error({
      action = "q2_ifindex_failed",
      ifname = ifname
    })
    return 
  end
  log_info({
    action = "q2_worker_start",
    ifname = ifname,
    ifindex = ifindex,
    redirect_url = redirect_url
  })
  return run_queue(QUEUE_CAPTIVE, handle_syn)
end
return {
  run = run
}
