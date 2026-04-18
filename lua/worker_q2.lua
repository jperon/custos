local ffi, libc, libnfq
do
  local _obj_0 = require("ffi_defs")
  ffi, libc, libnfq = _obj_0.ffi, _obj_0.libc, _obj_0.libnfq
end
local QUEUE_CAPTIVE
QUEUE_CAPTIVE = require("config").QUEUE_CAPTIVE
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
local get_l2, ETH_OFFSET
do
  local _obj_0 = require("parse/ethernet")
  get_l2, ETH_OFFSET = _obj_0.get_l2, _obj_0.ETH_OFFSET
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
local flags
flags = require("ipparse.l4.tcp").flags
local SYN, ACK, FIN, PSH
SYN, ACK, FIN, PSH = flags.SYN, flags.ACK, flags.FIN, flags.PSH
local get_mac
get_mac = require("neigh").get_mac
local AF_PACKET = 17
local SOCK_RAW = 3
local ETH_P_ALL = 0x0300
local PROTO_TCP = 6
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
  local fd = libc.socket(AF_PACKET, SOCK_RAW, ETH_P_ALL)
  if fd < 0 then
    return nil, "socket() failed: " .. tostring(ffi.errno())
  end
  return fd
end
local send_frame
send_frame = function(fd, frame, ifindex)
  local sll = ffi.new("struct sockaddr_ll")
  ffi.fill(sll, ffi.sizeof(sll), 0)
  sll.sll_family = AF_PACKET
  sll.sll_protocol = ETH_P_ALL
  sll.sll_ifindex = ifindex
  local n = libc.sendto(fd, frame, #frame, 0, ffi.cast("const struct sockaddr*", sll), ffi.sizeof(sll))
  return n == #frame
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
  local l2 = get_l2(nfad, raw)
  local ip, ip_off, tcp, tcp_off = parse_syn(raw)
  if not (ip) then
    log_warn({
      action = "q2_parse_failed",
      queue = 2,
      len = payload_len
    })
    return NF_DROP
  end
  local client_mac
  if l2.mac_raw and l2.mac_raw ~= "\0\0\0\0\0\0" then
    client_mac = l2.mac_raw
  end
  local bridge_mac = nil
  local bridge_mac_str = nil
  local bridge_ifname = "br"
  local fh = io.open("/sys/class/net/" .. tostring(bridge_ifname) .. "/address", "r")
  if fh then
    bridge_mac_str = fh:read(("*a"):gsub("\n", ""))
    fh:close()
    if bridge_mac_str and #bridge_mac_str > 0 then
      bridge_mac = s2mac(bridge_mac_str)
    end
  end
  local eth = new({
    src = client_mac or "\xFF\xFF\xFF\xFF\xFF\xFF",
    dst = bridge_mac or "\0\0\0\0\0\0",
    protocol = ip.version == 4 and IP4 or IP6
  })
  local eth_off = 1
  local send
  send = function(f)
    local res = send_frame(raw_fd, f, ifindex)
    if not (res) then
      log_warn({
        action = "q2_frame_send_error",
        queue = 2,
        ip = ip2s(ip.src)
      })
    end
    return res
  end
  local ok, err = pcall(function()
    local f1, f2, f3 = build_response_frames(eth, ip, tcp, redirect_url)
    log_info({
      action = "q2_sending_frames",
      queue = 2,
      ip = ip2s(ip.src, {
        frames = 3
      })
    })
    send(f1)
    send(f2)
    return send(f3)
  end)
  if ok then
    local fields = {
      action = "captive_redirect_q2",
      queue = 2,
      ip = ip2s(ip.src),
      sport = tcp.spt,
      mac = mac2s(l2.mac_raw),
      url = redirect_url
    }
    if l2.mac_src and l2.mac_src ~= "unknown" then
      fields.mac = l2.mac_src
    end
    log_info(fields)
  else
    log_warn({
      action = "q2_send_failed",
      queue = 2,
      err = tostring(err),
      ip = ip2s(ip.src)
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
        return u:connect("1.1.1.1", 80)
      end)
      local ip = u:getsockname()
      u:close()
      if ip and ip ~= "" and ip ~= "0.0.0.0" then
        local_ip = ip
      end
    end)
  end
  local host_part = local_ip:find(":", 1, true) and "[" .. tostring(local_ip) .. "]" or local_ip
  redirect_url = "https://" .. tostring(host_part) .. ":" .. tostring(https_port) .. "/"
  local fd, err = open_raw_socket(ifname)
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
