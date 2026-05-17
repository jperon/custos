local ffi, libnfq
do
  local _obj_0 = require("ffi_defs")
  ffi, libnfq = _obj_0.ffi, _obj_0.libnfq
end
local run_queue, NF_ACCEPT
do
  local _obj_0 = require("nfq_loop")
  run_queue, NF_ACCEPT = _obj_0.run_queue, _obj_0.NF_ACCEPT
end
local get_l2
get_l2 = require("nfq/ethernet").get_l2
local log_info, log_warn, log_debug, set_action_prefix
do
  local _obj_0 = require("log")
  log_info, log_warn, log_debug, set_action_prefix = _obj_0.log_info, _obj_0.log_warn, _obj_0.log_debug, _obj_0.set_action_prefix
end
local ipparse_ip = require("ipparse.l3.ip")
local ipparse_udp = require("ipparse.l4.udp")
local ipparse_tcp = require("ipparse.l4.tcp")
local sip_parser = require("sip.parser")
local ok_mac_ipc, mac_ipc = pcall(function()
  return require("mac_learner_ipc")
end)
local sip_ttl = nil
local ip_to_mac = { }
local IP_MAC_MAX = 256
local format_ip
format_ip = function(version, raw)
  if not (raw) then
    return nil
  end
  local ip2s = require("ipparse.l3.ip").ip2s
  if version == 4 then
    return ip2s(raw:sub(1, 4))
  elseif version == 6 then
    return ip2s(raw)
  else
    return nil
  end
end
local cache_ip_to_mac
cache_ip_to_mac = function(ip, mac)
  if not (ip and mac and mac ~= "unknown") then
    return 
  end
  if ip_to_mac[ip] then
    return 
  end
  local count = 0
  for _ in pairs(ip_to_mac) do
    count = count + 1
  end
  if count >= IP_MAC_MAX then
    local first_k = next(ip_to_mac)
    if first_k then
      ip_to_mac[first_k] = nil
    end
  end
  ip_to_mac[ip] = mac
end
local known_phone_mac
known_phone_mac = function(ip)
  if not (ip) then
    return nil
  end
  return ip_to_mac[ip]
end
local is_lan_ip
is_lan_ip = function(ip)
  if not (ip) then
    return false
  end
  if ip:match("^10%.") then
    return true
  end
  if ip:match("^192%.168%.") then
    return true
  end
  do
    local b = tonumber(ip:match("^172%.(%d+)%."))
    if b then
      if b >= 16 and b <= 31 then
        return true
      end
    end
  end
  if ip:match("^[Ff][CcDd][0-9a-fA-F:]*$") then
    return true
  end
  return false
end
local query_phone_mac
query_phone_mac = function(ip)
  if not (is_lan_ip(ip)) then
    return nil
  end
  if not (ok_mac_ipc and mac_ipc and mac_ipc.get_mac and ip) then
    return nil
  end
  local mac = mac_ipc.get_mac(ip)
  if not (mac and mac ~= "unknown") then
    return nil
  end
  cache_ip_to_mac(ip, mac)
  return mac
end
local resolve_outbound_mac
resolve_outbound_mac = function(ip_src_str, packet_mac)
  local mac = known_phone_mac(ip_src_str)
  if mac then
    return mac, "cache"
  end
  if is_lan_ip(ip_src_str) and packet_mac and packet_mac ~= "unknown" then
    return packet_mac, "packet"
  end
  mac = query_phone_mac(ip_src_str)
  if mac then
    return mac, "learner"
  end
  return nil, "none"
end
local classify_direction
classify_direction = function(sport, dport, ip_src_str, ip_dst_str)
  local outbound = (dport == 5060)
  local inbound = (sport == 5060)
  if not (outbound or inbound) then
    return false, false, false
  end
  if outbound and inbound then
    if known_phone_mac(ip_dst_str) then
      outbound = false
    else
      inbound = false
    end
  elseif outbound and (not inbound) and known_phone_mac(ip_dst_str) then
    outbound = false
    inbound = true
  elseif inbound and (not outbound) and known_phone_mac(ip_src_str) then
    inbound = false
    outbound = true
  end
  return outbound, inbound, true
end
local allow_mac_ip
allow_mac_ip = function(mac, ip, family, reason)
  if not (mac and mac ~= "unknown" and ip and family) then
    return 
  end
  local nft_q = require("nft_queue")
  local ok
  if family == "ip6" then
    ok = nft_q.add_mac6(mac, ip, nil, sip_ttl, reason)
  else
    ok = nft_q.add_mac4(mac, ip, nil, sip_ttl, reason)
  end
  if ok then
    local pending = nft_q.get_last_seq()
    if pending then
      nft_q.wait_ack(pending, reason)
    end
  end
  return ok
end
local allow_sip_peer
allow_sip_peer = function(ip, family, reason)
  if not (ip and family) then
    return 
  end
  local nft_q = require("nft_queue")
  if family == "ip6" then
    return nft_q.add_sip6(ip, nil, sip_ttl, reason)
  else
    return nft_q.add_sip4(ip, nil, sip_ttl, reason)
  end
end
local handle_packet
handle_packet = function(qh_ptr, nfad, pkt_id)
  local l2 = get_l2(nfad)
  local mac = l2.mac_src
  local payload_ptr = ffi.new("unsigned char*[1]")
  local payload_len = libnfq.nfq_get_payload(nfad, payload_ptr)
  if payload_len <= 0 then
    return NF_ACCEPT
  end
  local raw = ffi.string(payload_ptr[0], payload_len)
  local ip, ip_err = ipparse_ip.parse(raw, 1)
  if not (ip) then
    log_debug({
      action = "ip_parse_failed",
      pkt_id = pkt_id,
      err = ip_err or ""
    })
    return NF_ACCEPT
  end
  local ip_version = ip.version
  local ip_src_str = format_ip(ip_version, ip.src)
  local ip_dst_str = format_ip(ip_version, ip.dst)
  local ip_family
  if ip_version == 6 then
    ip_family = "ip6"
  else
    ip_family = "ip4"
  end
  local sport, dport, l7_payload = nil, nil, nil
  if ip.protocol == 17 then
    local ok_udp, udp = pcall(function()
      return ipparse_udp.parse(raw, ip.data_off)
    end)
    if ok_udp and udp then
      sport = udp.spt
      dport = udp.dpt
      if udp.data_off and udp.data_off <= #raw then
        l7_payload = raw:sub(udp.data_off)
      end
    end
  elseif ip.protocol == 6 then
    local ok_tcp, tcp = pcall(function()
      return ipparse_tcp.parse(raw, ip.data_off)
    end)
    if ok_tcp and tcp then
      sport = tcp.spt
      dport = tcp.dpt
      if tcp.data_off and tcp.data_off <= #raw then
        l7_payload = raw:sub(tcp.data_off)
      end
    end
  end
  if not (sport and dport) then
    return NF_ACCEPT
  end
  if ip.protocol == 17 and dport == 3478 then
    if ip_dst_str and mac ~= "unknown" then
      allow_mac_ip(mac, ip_dst_str, ip_family, "sip_stun")
      log_debug({
        action = "stun_ip_added",
        mac = mac,
        ip = ip_dst_str
      })
    end
    return NF_ACCEPT
  end
  if ip.protocol == 17 and sport == 3478 then
    if ip_src_str and ip_dst_str then
      allow_sip_peer(ip_src_str, ip_family, "stun_src")
      allow_sip_peer(ip_dst_str, ip_family, "stun_dst")
    end
    log_debug({
      action = "stun_response_accepted",
      ip = ip_src_str,
      dst = ip_dst_str
    })
    return NF_ACCEPT
  end
  if dport == 5061 or sport == 5061 then
    return NF_ACCEPT
  end
  local outbound, inbound, is_sip = classify_direction(sport, dport, ip_src_str, ip_dst_str)
  if not (is_sip) then
    return NF_ACCEPT
  end
  local outbound_mac = nil
  local outbound_mac_src = "none"
  if outbound then
    outbound_mac, outbound_mac_src = resolve_outbound_mac(ip_src_str, mac)
    log_debug({
      action = "sip_outbound_mac_selected",
      ip_src = ip_src_str or "",
      packet_mac = mac or "",
      selected_mac = outbound_mac or "",
      source = outbound_mac_src
    })
  end
  if outbound and ip_dst_str and outbound_mac then
    allow_mac_ip(outbound_mac, ip_dst_str, ip_family, "sip_signal")
    if ip_src_str and is_lan_ip(ip_src_str) then
      cache_ip_to_mac(ip_src_str, outbound_mac)
    end
  end
  if not (l7_payload and #l7_payload > 4) then
    return NF_ACCEPT
  end
  local msg = sip_parser.parse(l7_payload)
  if not (msg) then
    return NF_ACCEPT
  end
  allow_sip_peer(ip_src_str, ip_family, "sip_peer_src")
  allow_sip_peer(ip_dst_str, ip_family, "sip_peer_dst")
  local dst_phone_mac = known_phone_mac(ip_dst_str) or query_phone_mac(ip_dst_str)
  if not (msg and msg.sdp_ips and #msg.sdp_ips > 0) then
    return NF_ACCEPT
  end
  local target_mac = nil
  if outbound then
    target_mac = outbound_mac
    if not (target_mac) then
      log_debug({
        action = "sip_no_mac_for_src",
        ip_src = ip_src_str or "unknown"
      })
      return NF_ACCEPT
    end
  elseif inbound then
    target_mac = dst_phone_mac
    if not (target_mac) then
      log_debug({
        action = "sip_no_mac_for_dst",
        ip_dst = ip_dst_str or "unknown"
      })
      return NF_ACCEPT
    end
  end
  local _list_0 = msg.sdp_ips
  for _index_0 = 1, #_list_0 do
    local entry = _list_0[_index_0]
    allow_sip_peer(entry.ip, entry.family, "sip_media")
    allow_mac_ip(target_mac, entry.ip, entry.family, "sip_media")
    log_debug({
      action = "sip_media_ip_added",
      mac = target_mac,
      media_ip = entry.ip,
      family = entry.family,
      direction = (function()
        if inbound then
          return "inbound"
        else
          return "outbound"
        end
      end)(),
      cseq_method = msg.cseq_method or "",
      sip_status = tostring(msg.status_code or ""),
      sip_method = msg.method or ""
    })
  end
  return NF_ACCEPT
end
local run
run = function(queue_num, fds)
  set_action_prefix("sip_")
  local cfg = require("config")
  sip_ttl = (cfg.nft and cfg.nft.sip_session_ttl) or (cfg.nft and cfg.nft.ip_timeout) or "5m"
  if type(fds) == "table" then
    local nft_q = require("nft_queue")
    if fds.nft_wfd then
      nft_q.set_wfd(fds.nft_wfd)
    end
    if fds.ack_rfd and fds.worker_idx ~= nil then
      nft_q.set_ack_rfd(fds.ack_rfd, fds.worker_idx)
    end
  end
  log_info({
    action = "worker_sip_starting",
    queue = queue_num,
    ttl = sip_ttl
  })
  return run_queue(tonumber(queue_num), handle_packet)
end
return {
  run = run,
  classify_direction = classify_direction,
  resolve_outbound_mac = resolve_outbound_mac,
  remember_phone_ip = cache_ip_to_mac
}
