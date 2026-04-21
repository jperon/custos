local ffi, libc, libnfq
do
  local _obj_0 = require("ffi_defs")
  ffi, libc, libnfq = _obj_0.ffi, _obj_0.libc, _obj_0.libnfq
end
local QUEUE_CAPTIVE, AUTH_SESSIONS_FILE
do
  local _obj_0 = require("config")
  QUEUE_CAPTIVE, AUTH_SESSIONS_FILE = _obj_0.QUEUE_CAPTIVE, _obj_0.AUTH_SESSIONS_FILE
end
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
local user_for_ip
user_for_ip = require("auth.sessions").user_for_ip
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
local redirect_url4 = nil
local redirect_url6 = nil
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
  local client_ip_str = ip2s(ip.src)
  local client_mac_str = l2.mac_src
  if not client_mac_str or client_mac_str == "unknown" then
    client_mac_str = get_mac(client_ip_str)
  end
  local user = user_for_ip(client_ip_str, AUTH_SESSIONS_FILE, client_mac_str)
  local send
  send = function(f)
    local res = send_frame(raw_fd, f, ifindex)
    if not (res) then
      log_warn({
        action = "q2_frame_send_error",
        queue = 2,
        ip = client_ip_str,
        user = user
      })
    end
    return res
  end
  local ok, err = pcall(function()
    local url
    if ip.version == 6 then
      url = redirect_url6 or redirect_url4
    else
      url = redirect_url4 or redirect_url6
    end
    if not (url) then
      log_warn({
        action = "q2_no_redirect_url",
        queue = 2,
        ip = client_ip_str,
        version = ip.version,
        user = user
      })
      return 
    end
    local f1, f2, f3 = build_response_frames(eth, ip, tcp, url)
    log_info({
      action = "q2_sending_frames",
      queue = 2,
      ip = client_ip_str,
      frames = 3,
      url = url,
      user = user
    })
    send(f1)
    send(f2)
    return send(f3)
  end)
  if ok then
    local fields = {
      action = "captive_redirect_q2",
      queue = 2,
      ip = client_ip_str,
      sport = tcp.spt,
      mac = mac2s(l2.mac_raw),
      url = redirect_url,
      user = user
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
      ip = client_ip_str,
      user = user
    })
  end
  return NF_DROP
end
local run
run = function(auth_cfg)
  auth_cfg = auth_cfg or { }
  local ifname = auth_cfg.bridge_ifname or os.getenv("BRIDGE_IFNAME") or "br"
  local https_port = auth_cfg.port or 33443
  local local_ip4 = auth_cfg.captive_ip4 or os.getenv("CAPTIVE_IP4")
  local local_ip6 = auth_cfg.captive_ip6 or os.getenv("CAPTIVE_IP6")
  if not local_ip4 and not local_ip6 then
    local local_ip = auth_cfg.captive_ip or os.getenv("CAPTIVE_IP")
    if local_ip then
      if local_ip:find(":", 1, true) then
        local_ip6 = local_ip
      else
        local_ip4 = local_ip
      end
    end
  end
  local ok_sock, socket = pcall(require, "socket")
  if ok_sock then
    pcall(function()
      if not local_ip4 then
        local ok, out = pcall(function()
          local fh = io.popen("ip -4 addr show dev " .. tostring(ifname) .. " scope global 2>/dev/null | awk '/inet/{print $2}' | head -1 | cut -d'/' -f1")
          if not (fh) then
            return nil
          end
          local s = fh:read("*a")
          fh:close()
          s = s:gsub("%s+", "")
          return s
        end)
        if ok and out and out ~= "" and out ~= "0.0.0.0" then
          local_ip4 = out
        end
      end
      if not local_ip4 then
        local u = socket.udp()
        local ok_conn, _ = pcall(function()
          return u:connect("1.1.1.1", 80)
        end)
        if ok_conn then
          local ok_get, ip = pcall(function()
            return u:getsockname()
          end)
          if ok_get and ip and ip ~= "" and ip ~= "0.0.0.0" then
            local_ip4 = ip
          end
        end
      end
      if not local_ip6 then
        local ok_conn6, _ = pcall(function()
          return u:connect("2606:4700:4700::1111", 80)
        end)
        if ok_conn6 then
          local ok_get6, ip = pcall(function()
            return u:getsockname()
          end)
          if ok_get6 and ip and ip ~= "" and ip ~= "::" then
            local_ip6 = ip
          end
        else
          log_warn({
            action = "q2_ipv6_connect_failed",
            err = _ or "unknown"
          })
        end
      end
      return u:close()
    end)
  end
  if not local_ip6 then
    local bridge_ifname = auth_cfg.bridge_ifname or os.getenv("BRIDGE_IFNAME") or "br"
    local fh = io.open("/sys/class/net/" .. tostring(bridge_ifname) .. "/address", "r")
    if fh then
      fh:close()
      local ok, ip = pcall(function()
        local f = io.popen("ip -6 addr show dev " .. tostring(bridge_ifname) .. " scope global 2>/dev/null | awk '/inet6/{print $2}' | head -1 | cut -d'/' -f1")
        if f then
          local addr = f:read("*a")
          f:close()
          return addr:gsub("%s+", "")
        end
      end)
      if ok and ip and ip ~= "" and ip ~= "::" then
        local_ip6 = ip
        log_info({
          action = "q2_ipv6_from_interface",
          ip = local_ip6,
          ifname = bridge_ifname
        })
      end
    end
  end
  if local_ip4 then
    redirect_url4 = "https://" .. tostring(local_ip4) .. ":" .. tostring(https_port) .. "/"
  else
    log_warn({
      action = "q2_no_ipv4",
      msg = "No IPv4 captive IP configured"
    })
  end
  if local_ip6 then
    redirect_url6 = "https://[" .. tostring(local_ip6) .. "]:" .. tostring(https_port) .. "/"
  else
    log_warn({
      action = "q2_no_ipv6",
      msg = "No IPv6 captive IP configured"
    })
  end
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
    redirect_url4 = redirect_url4 or "not configured",
    redirect_url6 = redirect_url6 or "not configured"
  })
  return run_queue(QUEUE_CAPTIVE, handle_syn)
end
return {
  run = run
}
