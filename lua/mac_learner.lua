local ffi, libc
do
  local _obj_0 = require("ffi_defs")
  ffi, libc = _obj_0.ffi, _obj_0.libc
end
local _cfg = require("config")
local MAC_LEARNER_QUERY_SOCK = _cfg.MAC_LEARNER_QUERY_SOCK or "/var/run/custos/mac_query.sock"
local MAC_LEARNER_LEARN_MSG_SIZE = _cfg.MAC_LEARNER_LEARN_MSG_SIZE or 22
local MAC_LEARNER_ENTRY_TTL = _cfg.MAC_LEARNER_ENTRY_TTL or 300
local log_info, log_warn
do
  local _obj_0 = require("log")
  log_info, log_warn = _obj_0.log_info, _obj_0.log_warn
end
local bit = require("bit")
local AF_UNIX = 1
local SOCK_STREAM = 1
local POLLIN = 1
local AF_INET6 = 10
local mac_table = { }
local ip16_to_str
ip16_to_str = function(ip16)
  local is_ipv4 = true
  for i = 5, 16 do
    if ip16:byte(i) ~= 0 then
      is_ipv4 = false
      break
    end
  end
  if is_ipv4 then
    return tostring(ip16:byte(1)) .. "." .. tostring(ip16:byte(2)) .. "." .. tostring(ip16:byte(3)) .. "." .. tostring(ip16:byte(4))
  else
    local buf = ffi.new("uint8_t[16]")
    for i = 0, 15 do
      buf[i] = ip16:byte(i + 1)
    end
    local ntop = ffi.new("char[46]")
    libc.inet_ntop(AF_INET6, buf, ntop, 46)
    return ffi.string(ntop)
  end
end
local process_learn
process_learn = function(msg)
  if #msg < MAC_LEARNER_LEARN_MSG_SIZE then
    return 
  end
  local ip16 = msg:sub(1, 16)
  local mac_raw = msg:sub(17, 22)
  local all_zero = true
  for i = 1, 6 do
    if mac_raw:byte(i) ~= 0 then
      all_zero = false
      break
    end
  end
  if all_zero then
    return 
  end
  local ip_str = ip16_to_str(ip16)
  local mac_str = string.format("%02x:%02x:%02x:%02x:%02x:%02x", mac_raw:byte(1), mac_raw:byte(2), mac_raw:byte(3), mac_raw:byte(4), mac_raw:byte(5), mac_raw:byte(6))
  mac_table[ip_str] = {
    mac_str,
    os.time() + MAC_LEARNER_ENTRY_TTL
  }
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
    local now = os.time()
    local entry = mac_table[ip_str]
    if entry then
      if now <= entry[2] then
        resp = entry[1] .. "\n"
      else
        mac_table[ip_str] = nil
      end
    end
  end
  libc.send(client_fd, resp, #resp, 0)
  return libc.close(client_fd)
end
local create_server
create_server = function(path)
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
local run
run = function(learn_rfd)
  local query_sock = create_server(MAC_LEARNER_QUERY_SOCK)
  if query_sock < 0 then
    log_warn({
      action = "mac_learner_socket_failed",
      path = MAC_LEARNER_QUERY_SOCK
    })
    return 
  end
  log_info({
    action = "mac_learner_start",
    sock = MAC_LEARNER_QUERY_SOCK
  })
  local pfds = ffi.new("struct pollfd[2]")
  pfds[0].fd = learn_rfd
  pfds[0].events = POLLIN
  pfds[1].fd = query_sock
  pfds[1].events = POLLIN
  local learn_buf = ffi.new("uint8_t[?]", MAC_LEARNER_LEARN_MSG_SIZE)
  local purge_tick = 0
  while true do
    libc.poll(pfds, 2, 1000)
    if bit.band(pfds[0].revents, POLLIN) ~= 0 then
      while true do
        local n = libc.read(learn_rfd, learn_buf, MAC_LEARNER_LEARN_MSG_SIZE)
        if n <= 0 then
          break
        end
        if n == MAC_LEARNER_LEARN_MSG_SIZE then
          process_learn(ffi.string(learn_buf, MAC_LEARNER_LEARN_MSG_SIZE))
        end
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
        if now > entry[2] then
          mac_table[ip] = nil
        end
      end
    end
  end
end
return {
  run = run
}
