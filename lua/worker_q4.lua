local ffi, libc, libnfq
do
  local _obj_0 = require("ffi_defs")
  ffi, libc, libnfq = _obj_0.ffi, _obj_0.libc, _obj_0.libnfq
end
local QUEUE_MAC_LEARN, MAC_LEARNER_QUERY_SOCK, MAC_LEARNER_ENTRY_TTL
do
  local _obj_0 = require("config")
  QUEUE_MAC_LEARN, MAC_LEARNER_QUERY_SOCK, MAC_LEARNER_ENTRY_TTL = _obj_0.QUEUE_MAC_LEARN, _obj_0.MAC_LEARNER_QUERY_SOCK, _obj_0.MAC_LEARNER_ENTRY_TTL
end
local get_l2
get_l2 = require("parse/ethernet").get_l2
local log_info, log_warn, log_debug
do
  local _obj_0 = require("log")
  log_info, log_warn, log_debug = _obj_0.log_info, _obj_0.log_warn, _obj_0.log_debug
end
local bit = require("bit")
local AF_UNIX = 1
local SOCK_STREAM = 1
local POLLIN = 1
local READ_BUF_SIZE = 65536
local mac_table = { }
local payload_src_ip
payload_src_ip = function(p, len)
  if not (p and len and len > 0) then
    return nil
  end
  local ver = bit.rshift(p[0], 4)
  if ver == 4 then
    if len < 20 then
      return nil
    end
    return string.format("%d.%d.%d.%d", p[12], p[13], p[14], p[15])
  else
    if ver == 6 then
      if len < 40 then
        return nil
      end
      local buf = ffi.new("uint8_t[16]")
      for i = 0, 15 do
        buf[i] = p[8 + i]
      end
      local ntop = ffi.new("char[46]")
      libc.inet_ntop(10, buf, ntop, 46)
      return ffi.string(ntop)
    else
      return nil
    end
  end
end
local update_mac_table
update_mac_table = function(ip_str, mac_raw)
  if not (ip_str and ip_str ~= "" and mac_raw and #mac_raw == 6) then
    return 
  end
  local mac_str = string.format("%02x:%02x:%02x:%02x:%02x:%02x", mac_raw:byte(1), mac_raw:byte(2), mac_raw:byte(3), mac_raw:byte(4), mac_raw:byte(5), mac_raw:byte(6))
  mac_table[ip_str] = {
    mac = mac_str,
    expires = os.time() + MAC_LEARNER_ENTRY_TTL
  }
  return log_debug({
    action = "learned_ip_mac",
    ip = ip_str,
    mac = mac_str
  })
end
local process_nfq_packet
process_nfq_packet = function(nfad)
  local l2 = get_l2(nfad)
  local payload_ptr = ffi.new("unsigned char*[1]")
  local payload_len = libnfq.nfq_get_payload(nfad, payload_ptr)
  if payload_len <= 0 then
    return 
  end
  local p = ffi.cast("const uint8_t*", payload_ptr[0])
  local ip_str = payload_src_ip(p, tonumber(payload_len))
  if not ip_str then
    log_debug({
      action = "learn_skip_no_ip",
      mac_src = l2.mac_src,
      in_ifindex = l2.in_ifindex
    })
    return 
  end
  if l2.mac_src and l2.mac_src ~= "unknown" then
    return update_mac_table(ip_str, l2.mac_raw)
  else
    return log_debug({
      action = "learn_missing_mac",
      ip = ip_str,
      in_ifindex = l2.in_ifindex
    })
  end
end
local create_query_server
create_query_server = function(path)
  libc.unlink(path)
  local sock = libc.socket(AF_UNIX, SOCK_STREAM, 0)
  if sock < 0 then
    return -1
  end
  local addr = ffi.new("struct sockaddr_un")
  addr.sun_family = AF_UNIX
  ffi.copy(addr.sun_path, path)
  local addr_len = ffi.offsetof("struct sockaddr_un", "sun_path") + #path + 1
  if libc.bind(sock, ffi.cast("struct sockaddr*", addr), addr_len) ~= 0 then
    libc.close(sock)
    return -1
  end
  if libc.listen(sock, 8) ~= 0 then
    libc.close(sock)
    return -1
  end
  return sock
end
local handle_query
handle_query = function(client_fd)
  local buf = ffi.new("char[64]")
  local n = libc.recv(client_fd, buf, 63, 0)
  if n <= 0 then
    libc.close(client_fd)
    return 
  end
  local req = ffi.string(buf, n)
  local ip_str = req:match("^([^\n\r]+)")
  local resp = "unknown\n"
  if ip_str then
    local entry = mac_table[ip_str]
    if entry and os.time() <= entry.expires then
      resp = entry.mac .. "\n"
    else
      if entry then
        mac_table[ip_str] = nil
      end
    end
  end
  libc.send(client_fd, resp, #resp, 0)
  return libc.close(client_fd)
end
local run
run = function()
  local query_sock = create_query_server(MAC_LEARNER_QUERY_SOCK)
  if query_sock < 0 then
    log_warn({
      action = "mac_learner_socket_failed",
      path = MAC_LEARNER_QUERY_SOCK
    })
    return 
  end
  local h = libnfq.nfq_open()
  if h == nil then
    error("nfq_open() échoué")
  end
  libnfq.nfq_bind_pf(h, 2)
  libnfq.nfq_bind_pf(h, 10)
  libnfq.nfq_bind_pf(h, 7)
  local qh_box = ffi.new("nfq_q_handle*[1]")
  local process_packet_wrap
  process_packet_wrap = function(nfad)
    local ok, err = pcall(process_nfq_packet, nfad)
    if not (ok) then
      return log_warn({
        action = "nfq_process_failed",
        err = tostring(err)
      })
    end
  end
  local c_callback = ffi.cast("nfq_callback", function(qh, nfmsg, nfad, data)
    local raw_hdr = libnfq.nfq_get_msg_packet_hdr(nfad)
    local pkt_id = libc.ntohl(raw_hdr.packet_id)
    pcall(process_packet_wrap, nfad)
    libnfq.nfq_set_verdict(qh_box[0], pkt_id, 1, 0, nil)
    return 0
  end)
  local qh = libnfq.nfq_create_queue(h, QUEUE_MAC_LEARN, c_callback, nil)
  if qh == nil then
    error("nfq_create_queue(" .. tostring(QUEUE_MAC_LEARN) .. ") échoué")
  end
  qh_box[0] = qh
  libnfq.nfq_set_mode(qh, 2, READ_BUF_SIZE)
  local fd = libnfq.nfq_fd(h)
  local buf = ffi.new("char[?]", READ_BUF_SIZE)
  log_info({
    action = "worker_q4_start",
    queue = QUEUE_MAC_LEARN,
    sock = MAC_LEARNER_QUERY_SOCK
  })
  local pfds = ffi.new("struct pollfd[2]")
  pfds[0].fd = fd
  pfds[0].events = POLLIN
  pfds[1].fd = query_sock
  pfds[1].events = POLLIN
  local purge_tick = 0
  while true do
    libc.poll(pfds, 2, 1000)
    if bit.band(pfds[0].revents, POLLIN) ~= 0 then
      local rv = libc.read(fd, buf, READ_BUF_SIZE)
      if rv > 0 then
        libnfq.nfq_handle_packet(h, buf, tonumber(rv))
      end
    end
    if bit.band(pfds[1].revents, POLLIN) ~= 0 then
      local client_fd = libc.accept(query_sock, nil, nil)
      if client_fd >= 0 then
        handle_query(client_fd)
      end
    end
    purge_tick = purge_tick + 1
    if purge_tick >= 60 then
      purge_tick = 0
      local now = os.time()
      for ip, entry in pairs(mac_table) do
        if now > entry.expires then
          mac_table[ip] = nil
        end
      end
    end
  end
  libnfq.nfq_destroy_queue(qh)
  libnfq.nfq_close(h)
  return c_callback:free()
end
return {
  run = run
}
