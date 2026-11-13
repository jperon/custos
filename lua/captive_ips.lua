local log_info, log_warn
do
  local _obj_0 = require("log")
  log_info, log_warn = _obj_0.log_info, _obj_0.log_warn
end
local shquote
shquote = require("lib.shquote").shquote
local RETRY_INTERVAL = 10
local domain_from_url
domain_from_url = function(url)
  if not (url) then
    return nil
  end
  local host = url:match("^https?://([^/:]+)")
  if not (host) then
    return nil
  end
  if host:match("^%d+%.%d+%.%d+%.%d+$") then
    return nil
  end
  if host:match("^%[") then
    return nil
  end
  return host:lower()
end
local detect_ip4
detect_ip4 = function(auth_cfg, ifname)
  auth_cfg = auth_cfg or { }
  ifname = ifname or (auth_cfg.bridge_ifname or "br0")
  local local_ip4 = auth_cfg.captive_ip4 or os.getenv("CAPTIVE_IP4")
  if not local_ip4 then
    local ok, out = pcall(function()
      local fh = io.popen("ip -4 addr show dev " .. tostring(shquote(ifname)) .. " scope global 2>/dev/null | awk '/inet/{print $2}' | head -1 | cut -d'/' -f1")
      if not (fh) then
        return nil
      end
      local s = fh:read("*a")
      fh:close()
      return s:gsub("%s+", "")
    end)
    if ok and out and out ~= "" and out ~= "0.0.0.0" then
      local_ip4 = out
      log_info(function()
        return {
          action = "captive_ip4_autodetected",
          ip = local_ip4,
          ifname = ifname
        }
      end)
    end
  end
  if not local_ip4 then
    local ok_sock, socket = pcall(require, "socket")
    if ok_sock then
      pcall(function()
        local ok_udp, u = pcall(socket.udp)
        u = ok_udp and u or nil
        if u then
          local ok_conn, _ = pcall(u.connect, u, "1.1.1.1", 80)
          if ok_conn then
            local ok_get, ip = pcall(u.getsockname, u)
            if ok_get and ip and ip ~= "" and ip ~= "0.0.0.0" then
              local_ip4 = ip
              log_info(function()
                return {
                  action = "captive_ip4_autodetected_socket",
                  ip = local_ip4
                }
              end)
            end
          end
          return u:close()
        end
      end)
    end
  end
  return local_ip4
end
local detect_ip6
detect_ip6 = function(auth_cfg, ifname)
  auth_cfg = auth_cfg or { }
  ifname = ifname or (auth_cfg.bridge_ifname or "br0")
  local local_ip6 = auth_cfg.captive_ip6 or os.getenv("CAPTIVE_IP6")
  if not local_ip6 then
    local ok, ip = pcall(function()
      local f = io.popen("ip -6 addr show dev " .. tostring(shquote(ifname)) .. " scope global 2>/dev/null | awk '/inet6/{print $2}' | head -1 | cut -d'/' -f1")
      if not (f) then
        return nil
      end
      local addr = f:read("*a")
      f:close()
      return addr:gsub("%s+", "")
    end)
    if ok and ip and ip ~= "" and ip ~= "::" then
      local_ip6 = ip
      log_info(function()
        return {
          action = "captive_ip6_autodetected",
          ip = local_ip6,
          ifname = ifname
        }
      end)
    end
  end
  return local_ip6
end
local detect
detect = function(auth_cfg)
  auth_cfg = auth_cfg or { }
  local ifname = auth_cfg.bridge_ifname or "br0"
  return detect_ip4(auth_cfg, ifname), detect_ip6(auth_cfg, ifname)
end
local new_detector
new_detector = function(auth_cfg)
  auth_cfg = auth_cfg or { }
  local ifname = auth_cfg.bridge_ifname or "br0"
  local d = {
    auth_cfg = auth_cfg,
    ifname = ifname,
    ip4 = nil,
    ip6 = nil,
    last4 = 0,
    last6 = 0
  }
  local now = os.time()
  d.last4 = now
  local v4 = detect_ip4(auth_cfg, ifname)
  if v4 then
    d.ip4 = v4
  end
  d.last6 = now
  local v6 = detect_ip6(auth_cfg, ifname)
  if v6 then
    d.ip6 = v6
  end
  d.ensure = function(self, now_ts)
    now_ts = now_ts or os.time()
    if not self.ip4 then
      if now_ts - self.last4 >= RETRY_INTERVAL then
        self.last4 = now_ts
        local v = detect_ip4(self.auth_cfg, self.ifname)
        if v then
          self.ip4 = v
        end
      end
    end
    if not self.ip6 then
      if now_ts - self.last6 >= RETRY_INTERVAL then
        self.last6 = now_ts
        local v = detect_ip6(self.auth_cfg, self.ifname)
        if v then
          self.ip6 = v
        end
      end
    end
    return self.ip4, self.ip6
  end
  d.get = function(self)
    return self.ip4, self.ip6
  end
  return d
end
return {
  detect = detect,
  detect_ip4 = detect_ip4,
  detect_ip6 = detect_ip6,
  domain_from_url = domain_from_url,
  new_detector = new_detector,
  RETRY_INTERVAL = RETRY_INTERVAL
}
