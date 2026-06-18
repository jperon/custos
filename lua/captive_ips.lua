local log_info, log_warn
do
  local _obj_0 = require("log")
  log_info, log_warn = _obj_0.log_info, _obj_0.log_warn
end
local shquote
shquote = require("lib.shquote").shquote
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
local detect
detect = function(auth_cfg)
  auth_cfg = auth_cfg or { }
  local ifname = auth_cfg.bridge_ifname or "br0"
  local local_ip4 = auth_cfg.captive_ip4 or os.getenv("CAPTIVE_IP4")
  local local_ip6 = auth_cfg.captive_ip6 or os.getenv("CAPTIVE_IP6")
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
  return local_ip4, local_ip6
end
return {
  detect = detect,
  domain_from_url = domain_from_url
}
