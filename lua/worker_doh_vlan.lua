local ffi, libc, libnfq
do
  local _obj_0 = require("ffi_defs")
  ffi, libc, libnfq = _obj_0.ffi, _obj_0.libc, _obj_0.libnfq
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
local get_mac
get_mac = require("mac_learner_ipc").get_mac
local ipparse_ip = require("ipparse.l3.ip")
local ipc_wfd = nil
local encode_vlan_msg
encode_vlan_msg = function(ip_version, ip_raw, vlan)
  if not (ip_raw) then
    return nil
  end
  vlan = vlan or 0
  local ip16
  if ip_version == 4 then
    if not (#ip_raw >= 4) then
      return nil
    end
    ip16 = ip_raw:sub(1, 4) .. string.rep("\0", 12)
  else
    if not (#ip_raw >= 16) then
      return nil
    end
    ip16 = ip_raw:sub(1, 16)
  end
  return ip16 .. string.char(math.floor(vlan / 256) % 256, vlan % 256)
end
local send_vlan_learn
send_vlan_learn = function(ip_version, ip_raw, vlan)
  if not (ipc_wfd and ipc_wfd >= 0) then
    return false
  end
  local msg = encode_vlan_msg(ip_version, ip_raw, vlan)
  if not (msg) then
    return false
  end
  local n = libc.write(ipc_wfd, msg, 18)
  return n == 18
end
local should_learn_untagged
should_learn_untagged = function(frame_mac, known_mac)
  if not (known_mac and known_mac ~= "" and known_mac ~= "unknown") then
    return true
  end
  if not (frame_mac and frame_mac ~= "" and frame_mac ~= "unknown") then
    return true
  end
  return frame_mac == known_mac
end
local handle_packet
handle_packet = function(qh_ptr, nfad, pkt_id)
  local l2 = get_l2(nfad)
  local vlan = (l2 and l2.vlan) or 0
  local payload_ptr = ffi.new("unsigned char*[1]")
  local payload_len = libnfq.nfq_get_payload(nfad, payload_ptr)
  if payload_len <= 0 then
    log_warn(function()
      return {
        action = "no_payload",
        pkt_id = pkt_id,
        payload_len = payload_len
      }
    end)
    return NF_ACCEPT
  end
  local raw = ffi.string(payload_ptr[0], payload_len)
  local ip, err = ipparse_ip.parse(raw, 1)
  if not (ip) then
    log_debug(function()
      return {
        action = "parse_failed",
        pkt_id = pkt_id,
        err = err
      }
    end)
    return NF_ACCEPT
  end
  if ip.src then
    if vlan == 0 then
      local frame_mac = l2 and l2.mac_src
      local ip_str = ipparse_ip.ip2s(ip.src)
      local known_mac = ip_str and get_mac(ip_str)
      if not (should_learn_untagged(frame_mac, known_mac)) then
        log_debug(function()
          return {
            action = "untagged_skip_nonadjacent",
            pkt_id = pkt_id,
            frame_mac = frame_mac or "unknown",
            known_mac = known_mac or "unknown"
          }
        end)
        return NF_ACCEPT
      end
    end
    local ok = send_vlan_learn(ip.version, ip.src, vlan)
    if not (ok) then
      log_warn(function()
        return {
          action = "ipc_failed",
          pkt_id = pkt_id,
          ip_version = ip.version
        }
      end)
    end
    log_debug(function()
      return {
        action = "vlan_learned",
        pkt_id = pkt_id,
        vlan = vlan
      }
    end)
  end
  return NF_ACCEPT
end
local run
run = function(queue_num, wfd)
  set_action_prefix("doh_vlan_")
  ipc_wfd = wfd
  log_info(function()
    return {
      action = "starting",
      queue = queue_num,
      ipc_fd = wfd
    }
  end)
  return run_queue(tonumber(queue_num), handle_packet)
end
return {
  run = run,
  handle_packet = handle_packet,
  send_vlan_learn = send_vlan_learn,
  encode_vlan_msg = encode_vlan_msg,
  should_learn_untagged = should_learn_untagged
}
