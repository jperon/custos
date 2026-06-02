local ffi, libc, libnfq
do
  local _obj_0 = require("ffi_defs")
  ffi, libc, libnfq = _obj_0.ffi, _obj_0.libc, _obj_0.libnfq
end
local config = require("config")
local parse_eth, new, mac2s, s2mac, IP6, IP4
do
  local _obj_0 = require("ipparse.l2.ethernet")
  parse_eth, new, mac2s, s2mac, IP6, IP4 = _obj_0.parse, _obj_0.new, _obj_0.mac2s, _obj_0.s2mac, _obj_0.proto.IP6, _obj_0.proto.IP4
end
local parse_ip, l3_proto, ip2s
do
  local _obj_0 = require("ipparse.l3.ip")
  parse_ip, l3_proto, ip2s = _obj_0.parse, _obj_0.proto, _obj_0.ip2s
end
local parse_tcp
parse_tcp = require("ipparse.l4.tcp").parse
local get_l2
get_l2 = require("nfq/ethernet").get_l2
local run_queue, NF_ACCEPT, NF_DROP
do
  local _obj_0 = require("nfq_loop")
  run_queue, NF_ACCEPT, NF_DROP = _obj_0.run_queue, _obj_0.NF_ACCEPT, _obj_0.NF_DROP
end
local log_info, log_warn, log_error, set_action_prefix
do
  local _obj_0 = require("log")
  log_info, log_warn, log_error, set_action_prefix = _obj_0.log_info, _obj_0.log_warn, _obj_0.log_error, _obj_0.set_action_prefix
end
local detect_captive_ips
detect_captive_ips = require("captive_ips").detect
local bridge_raw = require("bridge_raw")
local flags
flags = require("ipparse.l4.tcp").flags
local SYN, ACK, FIN, PSH
SYN, ACK, FIN, PSH = flags.SYN, flags.ACK, flags.FIN, flags.PSH
local mac_learner_ipc = require("mac_learner_ipc")
local user_for_mac
user_for_mac = require("auth.sessions").user_for_mac
local PROTO_TCP = l3_proto.TCP
local PROTO_UDP = l3_proto.UDP
local parse_syn
parse_syn = function(raw)
  local ip, ip_off = parse_ip(raw, 1)
  if not (ip) then
    return nil
  end
  local tcp, tcp_off = parse_tcp(raw, ip.data_off)
  if not (tcp) then
    return nil
  end
  return ip, ip_off, tcp, tcp_off
end
local build_response_frames
build_response_frames = function(eth, ip, tcp, redirect_url)
  local isn = math.random(0, 0x7FFFFFFF)
  local http_body = "HTTP/1.1 302 Found\r\nLocation: " .. tostring(redirect_url) .. "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
  local http_len = #http_body
  local their_seq_plus1 = (tcp.seq_n + 1) % 0x100000000
  tcp.spt, tcp.dpt = tcp.dpt, tcp.spt
  ip.src, ip.dst = ip.dst, ip.src
  eth.dst, eth.src = eth.src, eth.dst
  local build_frame
  build_frame = function(tcp_flags, payload_str, our_seq, their_ack)
    tcp.seq_n = our_seq
    tcp.ack_n = their_ack
    tcp.flags = tcp_flags
    tcp.window = 65535
    tcp.urg_ptr = 0
    tcp.data = payload_str or ""
    ip.ttl = ip.ttl or 64
    if ip.version == 4 then
      ip.protocol = PROTO_TCP
    else
      ip.next_header = PROTO_TCP
    end
    ip.data = tcp
    if ip.version == 4 then
      eth.protocol = 0x0800
    else
      eth.protocol = 0x86DD
    end
    eth.data = ip
    return tostring(eth)
  end
  local syn_ack = build_frame((SYN + ACK), nil, isn, their_seq_plus1)
  local data = build_frame((PSH + ACK), http_body, (isn + 1) % 0x100000000, their_seq_plus1)
  local fin_ack = build_frame((FIN + ACK), nil, (isn + 1 + http_len) % 0x100000000, their_seq_plus1)
  return syn_ack, data, fin_ack
end
local open_raw_socket
open_raw_socket = function(ifname)
  return bridge_raw.open_socket(ifname)
end
local send_frame
send_frame = function(fd, frame, ifindex)
  return bridge_raw.send(fd, frame, ifindex)
end
local raw_fd = nil
local ifindex = nil
local _bridge_mac = nil
local redirect_url4 = nil
local redirect_url6 = nil
local custom_redirect_url = nil
local handle_syn
handle_syn = function(qh_ptr, nfad, pkt_id)
  local payload_ptr = ffi.new("unsigned char*[1]")
  local payload_len = libnfq.nfq_get_payload(nfad, payload_ptr)
  if payload_len <= 0 then
    return NF_DROP
  end
  local raw = ffi.string(payload_ptr[0], payload_len)
  local l2 = get_l2(nfad)
  local ip, ip_off, tcp, tcp_off = parse_syn(raw)
  if not (ip) then
    log_warn(function()
      return {
        action = "parse_failed",
        queue = 2,
        len = payload_len,
        err = "parse_syn returned nil"
      }
    end)
    return NF_DROP
  end
  local client_mac
  if l2.mac_raw and l2.mac_raw ~= "\0\0\0\0\0\0" then
    client_mac = l2.mac_raw
  end
  local eth = new({
    src = client_mac or "\xFF\xFF\xFF\xFF\xFF\xFF",
    dst = _bridge_mac or "\0\0\0\0\0\0",
    protocol = ip.version == 4 and IP4 or IP6
  })
  local eth_off = 1
  local client_ip_str = ip2s(ip.src)
  local client_mac_str = l2.mac_src
  if not client_mac_str or client_mac_str == "unknown" then
    client_mac_str = mac_learner_ipc.get_mac(client_ip_str)
  end
  local user = user_for_mac(client_mac_str, client_ip_str, config.auth.sessions_file)
  local send
  send = function(f)
    local res = send_frame(raw_fd, f, ifindex)
    if not (res) then
      log_warn(function()
        return {
          action = "frame_send_error",
          queue = 2,
          ip = client_ip_str,
          user = user,
          err = "send_frame returned false"
        }
      end)
    end
    return res
  end
  local url = custom_redirect_url or ((function()
    if ip.version == 6 then
      return redirect_url6 or redirect_url4
    else
      return redirect_url4 or redirect_url6
    end
  end)())
  if not (url) then
    log_warn(function()
      return {
        action = "no_redirect_url",
        queue = 2,
        ip = client_ip_str,
        version = ip.version,
        user = user
      }
    end)
    return NF_DROP
  end
  local ok, err = pcall(function()
    local f1, f2, f3 = build_response_frames(eth, ip, tcp, url)
    log_info(function()
      return {
        action = "sending_frames",
        queue = 2,
        ip = client_ip_str,
        frames = 3,
        url = url,
        user = user
      }
    end)
    send(f1)
    send(f2)
    return send(f3)
  end)
  if ok then
    local fields = {
      action = "redirect_captive",
      queue = 2,
      ip = client_ip_str,
      sport = tcp.spt,
      mac = mac2s(l2.mac_raw),
      url = url,
      user = user
    }
    if l2.mac_src and l2.mac_src ~= "unknown" then
      fields.mac = l2.mac_src
    end
    log_info(function()
      return fields
    end)
  else
    log_warn(function()
      return {
        action = "send_failed",
        queue = 2,
        err = tostring(err),
        ip = client_ip_str,
        user = user
      }
    end)
  end
  return NF_DROP
end
local run
run = function(queue_num, auth_cfg)
  set_action_prefix("captive_")
  auth_cfg = auth_cfg or { }
  local ifname = auth_cfg.bridge_ifname or "br0"
  local https_port = auth_cfg.port or 33443
  custom_redirect_url = auth_cfg.redirect_url
  local local_ip4, local_ip6 = detect_captive_ips(auth_cfg)
  if local_ip4 then
    redirect_url4 = "https://" .. tostring(local_ip4) .. ":" .. tostring(https_port) .. "/"
  else
    log_warn(function()
      return {
        action = "no_ipv4",
        msg = "No IPv4 captive IP configured"
      }
    end)
  end
  if local_ip6 then
    redirect_url6 = "https://[" .. tostring(local_ip6) .. "]:" .. tostring(https_port) .. "/"
  else
    log_warn(function()
      return {
        action = "no_ipv6",
        msg = "No IPv6 captive IP configured"
      }
    end)
  end
  local fd, err = open_raw_socket(ifname)
  if not (fd) then
    log_error(function()
      return {
        action = "socket_failed",
        err = err,
        ifname = ifname
      }
    end)
    return 
  end
  raw_fd = fd
  ifindex = tonumber(ffi.C.if_nametoindex(ifname))
  if ifindex == 0 then
    local errno = tonumber(ffi.C.__errno_location()[0])
    log_error(function()
      return {
        action = "ifindex_failed",
        ifname = ifname,
        errno = errno
      }
    end)
    return 
  end
  _bridge_mac = bridge_raw.read_mac(ifname)
  log_info(function()
    return {
      action = "worker_start",
      ifname = ifname,
      ifindex = ifindex,
      custom_url = custom_redirect_url or "auto",
      redirect_url4 = redirect_url4 or "not configured",
      redirect_url6 = redirect_url6 or "not configured"
    }
  end)
  return run_queue(tonumber(queue_num), handle_syn)
end
return {
  run = run
}
