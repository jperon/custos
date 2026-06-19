local ffi, libc
do
  local _obj_0 = require("ffi_defs")
  ffi, libc = _obj_0.ffi, _obj_0.libc
end
local mac_prober = require("mac_prober")
local config = require("config")
local log_info, log_warn, log_debug
do
  local _obj_0 = require("log")
  log_info, log_warn, log_debug = _obj_0.log_info, _obj_0.log_warn, _obj_0.log_debug
end
local enrich_session_ip
enrich_session_ip = require("auth.sessions").enrich_session_ip
local ip2s
ip2s = require("ipparse.l3.ip").ip2s
local mac2s
mac2s = require("packet_utils").mac2s
local mac_cfg = config.mac_learner or { }
local auth_cfg = config.auth or { }
local PROBE_TIMEOUT_MS = 200
local NEGATIVE_TTL = 30
local PURGE_INTERVAL = 60
local bit = require("bit")
local AF_UNIX = 1
local SOCK_STREAM = 1
local POLLIN = 1
local sh_quote
sh_quote = function(s)
  return "'" .. tostring(s):gsub("'", "'\"'\"'") .. "'"
end
local ensure_parent_dir
ensure_parent_dir = function(path)
  local parent = tostring(path):match("^(.*)/[^/]+$")
  if not (parent and parent ~= "") then
    return true
  end
  local ret = os.execute("mkdir -p " .. tostring(sh_quote(parent)))
  return ret == 0 or ret == true
end
local mac_table = { }
local negative_cache = { }
local pending_queries = { }
local prober = nil
local vlan_table = { }
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
    return ip2s(ip16:sub(1, 4))
  else
    return ip2s(ip16)
  end
end
local learn_mac
learn_mac = function(ip_str, mac_str)
  local existing = mac_table[ip_str]
  local is_new = not existing or existing[1] ~= mac_str
  mac_table[ip_str] = {
    mac_str,
    os.time() + (mac_cfg.entry_ttl or 300)
  }
  if is_new then
    local ok, enriched = pcall(enrich_session_ip, mac_str, ip_str, auth_cfg.sessions_file)
    if ok and enriched then
      log_info(function()
        return {
          action = "session_enriched",
          ip = ip_str,
          mac = mac_str
        }
      end)
    end
  end
  local waiters = pending_queries[ip_str]
  if not (waiters) then
    return 
  end
  local resp = mac_str .. "\n"
  for _, w in ipairs(waiters) do
    libc.send(w[1], resp, #resp, 0)
    libc.close(w[1])
  end
  pending_queries[ip_str] = nil
end
local process_learn
process_learn = function(msg)
  local msg_size = mac_cfg.learn_msg_size or 22
  if #msg < msg_size then
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
  local mac_str = mac2s(mac_raw)
  return learn_mac(ip_str, mac_str)
end
local process_vlan_learn
process_vlan_learn = function(msg)
  if #msg < 18 then
    return 
  end
  local ip16 = msg:sub(1, 16)
  local vlan = msg:byte(17) * 256 + msg:byte(18)
  local ip_str = ip16_to_str(ip16)
  vlan_table[ip_str] = {
    vlan,
    os.time() + (mac_cfg.entry_ttl or 300)
  }
end
local vlan_lookup
vlan_lookup = function(ip_str)
  local entry = vlan_table[ip_str]
  if not (entry) then
    return nil
  end
  if os.time() <= entry[2] then
    return entry[1]
  else
    vlan_table[ip_str] = nil
    return nil
  end
end
local expire_pending
expire_pending = function()
  local now_ms = mac_prober.get_ms()
  local now_epoch = os.time()
  for ip_str, waiters in pairs(pending_queries) do
    local i = #waiters
    while i >= 1 do
      if now_ms > waiters[i][2] then
        libc.send(waiters[i][1], "unknown\n", 8, 0)
        libc.close(waiters[i][1])
        table.remove(waiters, i)
      end
      i = i - 1
    end
    if #waiters == 0 then
      pending_queries[ip_str] = nil
      negative_cache[ip_str] = now_epoch + NEGATIVE_TTL
    end
  end
end
local start_query
start_query = function(client_fd)
  local buf = ffi.new("char[64]")
  local n = libc.recv(client_fd, buf, 63, 0)
  if n <= 0 then
    libc.close(client_fd)
    return 
  end
  local req = ffi.string(buf, n)
  local vlan_ip = req:match("^vlan:([^\n\r]+)")
  if vlan_ip then
    local vid = vlan_lookup(vlan_ip)
    if vid then
      local resp = vid .. "\n"
      libc.send(client_fd, resp, #resp, 0)
    else
      libc.send(client_fd, "unknown\n", 8, 0)
    end
    libc.close(client_fd)
    return 
  end
  local ip_str = req:match("^([^\n\r]+)")
  if not (ip_str) then
    libc.send(client_fd, "unknown\n", 8, 0)
    libc.close(client_fd)
    return 
  end
  local now = os.time()
  local entry = mac_table[ip_str]
  if entry then
    if now <= entry[2] then
      local resp = entry[1] .. "\n"
      libc.send(client_fd, resp, #resp, 0)
      libc.close(client_fd)
      return 
    else
      mac_table[ip_str] = nil
    end
  end
  local neg_exp = negative_cache[ip_str]
  if neg_exp and now <= neg_exp then
    libc.send(client_fd, "unknown\n", 8, 0)
    libc.close(client_fd)
    return 
  end
  if prober then
    local expiry_ms = mac_prober.get_ms() + PROBE_TIMEOUT_MS
    if pending_queries[ip_str] then
      pending_queries[ip_str][#pending_queries[ip_str] + 1] = {
        client_fd,
        expiry_ms
      }
    else
      local ok, sent = pcall(mac_prober.send_probe, prober, ip_str)
      if ok and sent then
        pending_queries[ip_str] = {
          {
            client_fd,
            expiry_ms
          }
        }
        return 
      else
        negative_cache[ip_str] = now + NEGATIVE_TTL
      end
    end
    return 
  end
  libc.send(client_fd, "unknown\n", 8, 0)
  return libc.close(client_fd)
end
local create_server
create_server = function(path)
  if not (ensure_parent_dir(path)) then
    return -1
  end
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
run = function(learn_rfd, ifname, vlan_learn_rfd)
  ifname = ifname or "br"
  prober = mac_prober.init(ifname)
  if prober then
    log_info(function()
      return {
        action = "mac_prober_ready",
        ifname = ifname,
        ns_enabled = prober.ip6_fd ~= nil
      }
    end)
  else
    log_warn(function()
      return {
        action = "mac_prober_disabled",
        ifname = ifname
      }
    end)
  end
  local query_sock_path = mac_cfg.query_sock or config.MAC_LEARNER_QUERY_SOCK or "/var/run/custos/mac_query.sock"
  local query_sock = create_server(query_sock_path)
  if query_sock < 0 then
    local errno = tonumber(ffi.C.__errno_location()[0])
    log_warn(function()
      return {
        action = "mac_learner_socket_failed",
        path = query_sock_path,
        errno = errno
      }
    end)
    return 
  end
  log_info(function()
    return {
      action = "mac_learner_start",
      sock = query_sock_path
    }
  end)
  local pfds = ffi.new("struct pollfd[5]")
  pfds[0].fd = learn_rfd
  pfds[0].events = POLLIN
  pfds[1].fd = query_sock
  pfds[1].events = POLLIN
  local nfds = 2
  if prober then
    pfds[2].fd = prober.arp_fd
    pfds[2].events = POLLIN
    nfds = 3
    if prober.ip6_fd then
      pfds[3].fd = prober.ip6_fd
      pfds[3].events = POLLIN
      nfds = 4
    end
  end
  local vlan_idx = -1
  if vlan_learn_rfd then
    vlan_idx = nfds
    pfds[vlan_idx].fd = vlan_learn_rfd
    pfds[vlan_idx].events = POLLIN
    nfds = nfds + 1
  end
  local msg_size = mac_cfg.learn_msg_size or 22
  local learn_buf = ffi.new("uint8_t[?]", msg_size)
  local arp_buf = ffi.new("uint8_t[512]")
  local ipv6_buf = ffi.new("uint8_t[2048]")
  local vlan_buf = ffi.new("uint8_t[18]")
  local last_purge = 0
  while true do
    local poll_ms
    if next(pending_queries) ~= nil then
      poll_ms = 20
    else
      poll_ms = 1000
    end
    libc.poll(pfds, nfds, poll_ms)
    if bit.band(pfds[0].revents, POLLIN) ~= 0 then
      while true do
        local n = libc.read(learn_rfd, learn_buf, msg_size)
        if n <= 0 then
          break
        end
        if n == msg_size then
          process_learn(ffi.string(learn_buf, msg_size))
        end
      end
    end
    if bit.band(pfds[1].revents, POLLIN) ~= 0 then
      local client_fd = libc.accept(query_sock, nil, nil)
      if client_fd >= 0 then
        start_query(client_fd)
      end
    end
    if nfds >= 3 and bit.band(pfds[2].revents, POLLIN) ~= 0 then
      local n = libc.recv(prober.arp_fd, arp_buf, 512, 0)
      if n > 0 then
        local raw = ffi.string(arp_buf, n)
        local ip_str, mac_str = mac_prober.parse_arp_frame(raw, n)
        if ip_str and mac_str then
          learn_mac(ip_str, mac_str)
          log_debug(function()
            return {
              action = "mac_learned_arp",
              ip = ip_str,
              mac = mac_str
            }
          end)
        end
      end
    end
    if nfds >= 4 and bit.band(pfds[3].revents, POLLIN) ~= 0 then
      local n = libc.recv(prober.ip6_fd, ipv6_buf, 2048, 0)
      if n > 0 then
        local raw = ffi.string(ipv6_buf, n)
        local ip_str, mac_str = mac_prober.parse_na_frame(raw, n)
        if ip_str and mac_str then
          learn_mac(ip_str, mac_str)
          log_debug(function()
            return {
              action = "mac_learned_na",
              ip = ip_str,
              mac = mac_str
            }
          end)
        end
      end
    end
    if vlan_idx >= 0 and bit.band(pfds[vlan_idx].revents, POLLIN) ~= 0 then
      while true do
        local n = libc.read(vlan_learn_rfd, vlan_buf, 18)
        if n <= 0 then
          break
        end
        if n == 18 then
          process_vlan_learn(ffi.string(vlan_buf, 18))
        end
      end
    end
    if next(pending_queries) ~= nil then
      expire_pending()
    end
    local now_epoch = os.time()
    if now_epoch - last_purge >= PURGE_INTERVAL then
      last_purge = now_epoch
      for ip, entry in pairs(mac_table) do
        if now_epoch > entry[2] then
          mac_table[ip] = nil
        end
      end
      for ip, exp in pairs(negative_cache) do
        if now_epoch > exp then
          negative_cache[ip] = nil
        end
      end
      for ip, entry in pairs(vlan_table) do
        if now_epoch > entry[2] then
          vlan_table[ip] = nil
        end
      end
    end
  end
end
return {
  run = run,
  process_vlan_learn = process_vlan_learn,
  vlan_lookup = vlan_lookup
}
